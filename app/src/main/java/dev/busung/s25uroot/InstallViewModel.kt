package dev.busung.s25uroot

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

enum class InstallPhase {
    Checking,
    Ready,
    Downloading,
    Exploiting,
    LoadingKernelSu,
    Installed,
    Failed,
}

data class InstallUiState(
    val phase: InstallPhase = InstallPhase.Checking,
    val message: String = "",
    val probeOutput: String = "",
    val log: String = "",
) {
    val busy: Boolean
        get() = phase in setOf(
            InstallPhase.Checking,
            InstallPhase.Downloading,
            InstallPhase.Exploiting,
            InstallPhase.LoadingKernelSu,
        )

}

data class TargetCatalogUiState(
    val loading: Boolean = false,
    val profiles: List<TargetProfile> = emptyList(),
    val error: String? = null,
)

private data class CommandResult(val code: Int, val output: String)

/**
 * Payloads are truncated to a fixed release size, so a rebuild of a target --
 * or a different target padded to the same size -- has exactly the length of
 * whatever is already staged, and would keep running in its place.
 */
internal fun stagedFileIsCurrent(staged: File, source: File): Boolean {
    if (!staged.exists()) return false
    val stagedDigest = sha256OrNull(staged) ?: return false
    return stagedDigest == sha256OrNull(source)
}

private fun sha256OrNull(file: File): String? = runCatching {
    file.inputStream().use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }
}.getOrNull()

class InstallViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application
    private val repository = PayloadRepository(application)
    private val historyStore = InstallHistoryStore(application)
    private val mutableState = MutableStateFlow(InstallUiState())
    private val mutableHistory = MutableStateFlow(historyStore.closeInterruptedRuns())
    private val mutableTargetCatalog = MutableStateFlow(TargetCatalogUiState())
    private var discoveryJob: Job? = null
    private var installJob: Job? = null
    private var activeHistoryEntry: InstallHistoryEntry? = null

    @Volatile
    private var activeRunShizuku: Boolean? = null
    val state: StateFlow<InstallUiState> = mutableState.asStateFlow()
    val history: StateFlow<List<InstallHistoryEntry>> = mutableHistory.asStateFlow()
    val targetCatalog: StateFlow<TargetCatalogUiState> = mutableTargetCatalog.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        if (installJob?.isActive == true) return
        mutableHistory.value = historyStore.load()
        discoveryJob?.cancel()
        discoveryJob = viewModelScope.launch(Dispatchers.IO) {
            val probe = NativeProbe.run()
            if (detectInstalled()) {
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Installed,
                    message = app.getString(R.string.status_ksu_active),
                    probeOutput = probe,
                    log = probe,
                )
                return@launch
            }
            try {
                val profile = repository.resolveTarget(DeviceSnapshot.current())
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Ready,
                    message = app.getString(R.string.status_not_installed),
                    probeOutput = probe,
                    log = "$probe\n${app.getString(R.string.log_profile, profile.profileId)}",
                )
            } catch (error: Throwable) {
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Failed,
                    message = app.getString(R.string.status_support_failed),
                    probeOutput = probe,
                    log = "$probe\n[-] ${error.message ?: error.javaClass.simpleName}",
                )
            }
        }
    }

    fun deleteHistoryEntries(ids: Collection<String>) {
        val runningId = activeHistoryEntry?.id
        val toDelete = ids.filterNot { it == runningId }
        if (toDelete.isEmpty()) return
        toDelete.forEach(historyStore::delete)
        mutableHistory.value = mutableHistory.value.filterNot { it.id in toDelete }
    }

    fun loadTargetCatalog() {
        if (mutableTargetCatalog.value.loading) return
        viewModelScope.launch(Dispatchers.IO) {
            mutableTargetCatalog.value = TargetCatalogUiState(loading = true)
            mutableTargetCatalog.value = try {
                TargetCatalogUiState(
                    profiles = repository.loadTargets().sortedWith(
                        compareBy(
                            TargetProfile::displayName,
                            TargetProfile::profileId,
                        ),
                    ),
                )
            } catch (error: Throwable) {
                TargetCatalogUiState(error = error.message ?: error.javaClass.simpleName)
            }
        }
    }

    fun install(profileId: String? = null) {
        if (installJob?.isActive == true || mutableState.value.phase == InstallPhase.Installed) return
        discoveryJob?.cancel()
        installJob = viewModelScope.launch(Dispatchers.IO) {
            mutableState.value = InstallUiState(
                phase = InstallPhase.Checking,
                probeOutput = mutableState.value.probeOutput,
            )
            startHistory()
            // Freeze the transport for the whole run so a mid-run preference
            // change cannot mix Shizuku and standalone execution between the
            // exploit and the KernelSU staging steps.
            activeRunShizuku = AppPreferences.shizukuMode(app)
            try {
                if (shizukuEnabled()) {
                    appendLog(app.getString(R.string.log_shizuku_prepare))
                    if (!ShizukuController.isRunning() && !ShizukuController.pingUntilRunning()) {
                        error(app.getString(R.string.error_shizuku_unavailable))
                    }
                    if (!ShizukuController.isGranted() && !ShizukuController.requestPermission()) {
                        error(app.getString(R.string.error_shizuku_permission))
                    }
                    appendLog(app.getString(R.string.log_shizuku_permission))
                }
                setPhase(InstallPhase.Checking, app.getString(R.string.status_checking_github))
                val profile = if (profileId == null) {
                    repository.resolveTarget(DeviceSnapshot.current())
                } else {
                    repository.resolveTarget(profileId)
                }
                appendLog(app.getString(R.string.log_profile, profile.profileId))
                updateHistoryProfile(profile.profileId)

                setPhase(InstallPhase.Downloading, app.getString(R.string.status_downloading_payload))
                val payloads = repository.download(profile) { appendLog("[*] $it") }
                appendLog(app.getString(R.string.log_download_verified))

                setPhase(InstallPhase.Exploiting, app.getString(R.string.status_exploit_running))
                executeExploit(payloads)

                setPhase(InstallPhase.LoadingKernelSu, app.getString(R.string.status_ksu_loading))
                installKernelSu(payloads)

                setPhase(InstallPhase.Installed, app.getString(R.string.status_ksu_active))
                appendLog(app.getString(R.string.log_install_complete))
                finishHistory(InstallRunResult.Succeeded)
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
                setPhase(InstallPhase.Failed, app.getString(R.string.status_install_failed))
                finishHistory(InstallRunResult.Failed)
            } finally {
                activeRunShizuku = null
            }
        }
    }

    private suspend fun executeExploit(payloads: VerifiedPayloads) {
        val payload = payloads.exploit
        val shizuku = shizukuEnabled()
        val logFile = if (shizuku) File(SHIZUKU_LOG_PATH) else File(app.filesDir, "exploit.log")
        if (shizuku) {
            ShizukuController.exec(arrayOf("rm", "-f", SHIZUKU_LOG_PATH)).waitFor()
            // The payload's UMH root stage execs this exact path
            // (ROOT_UMH_PATH in target.h) — stage our root client there.
            shizukuStage(payloads.helper, SHIZUKU_ROOT_CLIENT_PATH, "755")
        } else {
            logFile.delete()
        }
        val helper = helperFile()
        if (!shizuku) {
            require(helper.canExecute()) { app.getString(R.string.error_helper_unavailable) }
        }
        val logPrefix = mutableState.value.log
        val bootToken = currentBootToken()
        val process = if (shizuku) {
            val stagedPayload = shizukuStage(payload, SHIZUKU_PAYLOAD_PATH, "755")
            ShizukuController.exec(
                arrayOf("/system/bin/sh", "-c", "true"),
                shizukuEnvironment(bootToken, stagedPayload.absolutePath, helper.absolutePath),
            )
        } else {
            val processBuilder = ProcessBuilder(
                helper.absolutePath,
                "--run-payload",
                payload.absolutePath,
                helper.absolutePath,
                logFile.absolutePath,
            ).redirectErrorStream(true)
            processBuilder.environment().apply {
                put("EXPLOIT_ATTEMPTS", EXPLOIT_ATTEMPTS)
                put("P0_ATTEMPT_TIMEOUT_SEC", P0_ATTEMPT_TIMEOUT_SEC)
                put("EXPLOIT_ATTEMPT_TIMEOUT_SEC", EXPLOIT_ATTEMPT_TIMEOUT_SEC)
                cachedP0Offset(bootToken)?.let { put(P0_OFFSET_ENV, it) }
            }
            processBuilder.start()
        }
        val captured = StringBuilder()
        val readLog: () -> String = if (shizuku) {
            { drainProcessOutput(process, captured) }
        } else {
            // Keep draining stdout while polling: if the helper fills the OS
            // pipe buffer it blocks on write and stops making log progress,
            // which would trip the stall detector spuriously.
            { drainProcessOutput(process, captured); logFile.readTextIfPresent() }
        }

        try {
            val startedAt = SystemClock.elapsedRealtime()
            var lastProgressAt = startedAt
            var lastRawLog = ""
            while (process.isAlive) {
                val rawLog = readLog()
                if (rawLog != lastRawLog) {
                    cacheP0Offset(bootToken, rawLog)
                    publishExploitLog(logPrefix, rawLog)
                    lastRawLog = rawLog
                    lastProgressAt = SystemClock.elapsedRealtime()
                }
                val now = SystemClock.elapsedRealtime()
                require(now - lastProgressAt < EXPLOIT_STALL_MILLIS) {
                    app.getString(R.string.error_exploit_stalled)
                }
                require(now - startedAt < EXPLOIT_TOTAL_MILLIS) {
                    app.getString(R.string.error_exploit_timeout)
                }
                delay(if (shizuku) SHIZUKU_LOG_POLL_INTERVAL else LOG_POLL_INTERVAL)
            }

            val exitCode = process.waitFor()
            val rawLog = readLog()
            cacheP0Offset(bootToken, rawLog)
            publishExploitLog(logPrefix, rawLog)
            // Both transports drain into `captured` during the poll loop, so
            // this never blocks on a child still holding the pipe open.
            val earlyOutput = captured.toString().trim()
            require(exitCode == 0) {
                app.getString(
                    R.string.error_payload_exit,
                    exitCode,
                    earlyOutput.takeIf(String::isNotBlank)?.let { " ($it)" } ?: "",
                )
            }
            require(rawLog.contains("exploit completed") && rawLog.contains("done=1 root=1")) {
                app.getString(R.string.error_success_marker)
            }
        } finally {
            if (process.isAlive) {
                process.destroy()
                delay(500.milliseconds)
                if (process.isAlive) process.destroyForcibly()
            }
        }
        appendLog(app.getString(R.string.log_bootstrap_root))
    }

    private fun drainProcessOutput(process: Process, buffer: StringBuilder): String {
        return try {
            drainStream(process.inputStream, buffer)
            drainStream(process.errorStream, buffer)
            buffer.toString()
        } catch (_: Throwable) {
            buffer.toString()
        }
    }

    private fun drainStream(stream: InputStream, buffer: StringBuilder) {
        val data = ByteArray(4096)
        while (stream.available() > 0) {
            val count = stream.read(data)
            if (count <= 0) break
            buffer.append(String(data, 0, count, Charsets.UTF_8))
        }
    }

    private fun publishExploitLog(prefix: String, rawLog: String) {
        mutableState.value = mutableState.value.copy(
            log = listOf(prefix, stripAnsi(rawLog))
                .filter(String::isNotBlank)
                .joinToString("\n"),
        )
        updateHistoryLog()
    }

    private suspend fun installKernelSu(payloads: VerifiedPayloads) {
        val clientPath: String
        val koPath: String
        val loaderPath: String
        if (shizukuEnabled()) {
            shizukuStage(payloads.helper, SHIZUKU_ROOT_CLIENT_PATH, "755")
            shizukuStage(payloads.ksuLoader, SHIZUKU_KSULOAD_PATH, "755")
            shizukuStage(payloads.kernelSu, SHIZUKU_KSU_KO_PATH, "755")
            clientPath = SHIZUKU_ROOT_CLIENT_PATH
            loaderPath = SHIZUKU_KSULOAD_PATH
            koPath = SHIZUKU_KSU_KO_PATH
            appendLog(app.getString(R.string.log_ksu_staged))
        } else {
            clientPath = payloads.helper.absolutePath
            loaderPath = payloads.ksuLoader.absolutePath
            koPath = payloads.kernelSu.absolutePath
        }

        // Late-load the Samsung KDP/RKP/DEFEX-patched KernelSU through the
        // temp-root channel: ksu-load.so rewrites every UNDEF symbol to
        // SHN_ABS (clearing TRIM_UNUSED_KSYMS/modversions/vermagic walls)
        // and calls init_module; the module itself never touches the
        // syscall table, so RKP stays quiet.
        val loadCmd = "echo 0 > /proc/sys/kernel/kptr_restrict; " +
            "KSU_KO_PATH=$koPath KSU_KO_PARAMS=allow_shell=1 " +
            "LD_PRELOAD=$loaderPath /system/bin/true"
        val loaded = runClient(arrayOf(clientPath, "-c", loadCmd))
        require(loaded.output.contains(KSU_LOAD_OK_MARKER)) {
            app.getString(R.string.error_ksu_verify, loaded.code, loaded.output)
        }
        if (loaded.output.isNotBlank()) appendLog(loaded.output)
        storeInstallReceipt()
        appendLog(app.getString(R.string.log_ksu_control_verified))
    }

    private fun detectInstalled(): Boolean {
        if (NativeProbe.isKernelSuActive()) return true
        val bootToken = currentBootToken() ?: return false
        val receipt = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
        return receipt.getString(RECEIPT_BOOT_TOKEN, null) == bootToken &&
            receipt.getBoolean(RECEIPT_VERIFIED, false)
    }

    private fun storeInstallReceipt() {
        val bootToken = currentBootToken() ?: error(app.getString(R.string.error_boot_id))
        val stored = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
            .edit()
            .putString(RECEIPT_BOOT_TOKEN, bootToken)
            .putBoolean(RECEIPT_VERIFIED, true)
            .commit()
        require(stored) { app.getString(R.string.error_receipt) }
    }

    private fun currentBootToken(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id")
            .readText(Charsets.US_ASCII)
            .trim()
            .takeIf(String::isNotBlank)
    }.getOrNull()

    private fun cachedP0Offset(bootToken: String?): String? {
        if (bootToken == null) return null
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) != bootToken) return null
        return stored.getString(P0_CACHE_OFFSET, null)
    }

    private fun cacheP0Offset(bootToken: String?, log: String) {
        if (bootToken == null) return
        val match = P0_OFFSET_PATTERN.findAll(log).lastOrNull() ?: return
        val offset = match.groupValues[1].toLongOrNull(16) ?: return
        if (offset !in 0..P0_OFFSET_MAX || offset and P0_OFFSET_MASK != 0L) return
        val value = "0x${offset.toString(16)}"
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) == bootToken &&
            stored.getString(P0_CACHE_OFFSET, null) == value
        ) return
        stored.edit()
            .putString(P0_CACHE_BOOT_TOKEN, bootToken)
            .putString(P0_CACHE_OFFSET, value)
            .apply()
    }

    private fun helperFile(): File =
        if (shizukuEnabled()) {
            shizukuStage(nativeHelperFile(), SHIZUKU_HELPER_PATH, "755")
        } else {
            nativeHelperFile()
        }

    private fun nativeHelperFile() = File(app.applicationInfo.nativeLibraryDir, "libcve43499root.so")

    private fun shizukuEnabled(): Boolean = activeRunShizuku ?: AppPreferences.shizukuMode(app)

    private fun shizukuStage(source: File, target: String, mode: String): File {
        val staged = File(target)
        if (stagedFileIsCurrent(staged, source)) return staged
        try {
            ShizukuController.writeFile(target, mode, source.inputStream())
        } catch (error: Throwable) {
            throw IllegalStateException(
                app.getString(R.string.error_shizuku_stage, target, error.message.orEmpty()),
                error,
            )
        }
        return staged
    }

    private fun shizukuEnvironment(
        bootToken: String?,
        payloadPath: String,
        helperPath: String,
    ): Array<String> = buildList {
        add("EXPLOIT_ATTEMPTS=$EXPLOIT_ATTEMPTS")
        add("P0_ATTEMPT_TIMEOUT_SEC=$P0_ATTEMPT_TIMEOUT_SEC")
        add("EXPLOIT_ATTEMPT_TIMEOUT_SEC=$EXPLOIT_ATTEMPT_TIMEOUT_SEC")
        add("CVE43499_ROOT_HELPER=$helperPath")
        add("LD_PRELOAD=$payloadPath")
        // Winning capture knobs (verified on SM-S9010): deep order-3 absorb
        // plus deeper skb reclaim sends; without them the leak page is
        // missed and the CFI stage reads a recycled/zeroed fops table.
        add("RECLAIM_ABSORB_MAX_PAGES=16384")
        add("PAGE_RECLAIM_SENDS=64")
        add("RECLAIM_ORDER0_MB=64")
        cachedP0Offset(bootToken)?.let { add("$P0_OFFSET_ENV=$it") }
    }.toTypedArray()

    /**
     * Runs the temp-root client for a management command (kernel load and
     * friends). Unlike the exploit run there is no log file to poll, so
     * output is drained inline and a hard deadline guards against a client
     * that never exits.
     */
    private suspend fun runClient(argv: Array<String>): CommandResult {
        val process = if (shizukuEnabled()) {
            ShizukuController.exec(argv)
        } else {
            ProcessBuilder(argv.toList())
                .redirectErrorStream(true)
                .start()
        }
        return awaitProcess(process)
    }

    private suspend fun awaitProcess(process: Process): CommandResult {
        val captured = StringBuilder()
        val startedAt = SystemClock.elapsedRealtime()
        try {
            while (process.isAlive) {
                drainProcessOutput(process, captured)
                require(SystemClock.elapsedRealtime() - startedAt < HELPER_TIMEOUT_MILLIS) {
                    app.getString(
                        R.string.error_helper_timeout,
                        captured.toString().trim().takeIf(String::isNotBlank)
                            ?.let { ": $it" } ?: "",
                    )
                }
                delay(HELPER_POLL_INTERVAL)
            }
            drainProcessOutput(process, captured)
            val exitCode = process.waitFor()
            return CommandResult(exitCode, stripAnsi(captured.toString().trim()))
        } finally {
            if (process.isAlive) {
                process.destroy()
                delay(500.milliseconds)
                if (process.isAlive) process.destroyForcibly()
            }
        }
    }

    private fun setPhase(phase: InstallPhase, message: String) {
        mutableState.value = mutableState.value.copy(phase = phase, message = message)
        appendLog("[*] $message")
    }

    private fun appendLog(line: String) {
        val cleanLine = stripAnsi(line).trim()
        if (cleanLine.isBlank()) return
        mutableState.value = mutableState.value.copy(
            log = (mutableState.value.log + "\n" + cleanLine).trim(),
        )
        updateHistoryLog()
    }

    private fun startHistory() {
        val entry = historyStore.create()
        activeHistoryEntry = entry
        publishHistory(entry)
    }

    private fun updateHistory(transform: (InstallHistoryEntry) -> InstallHistoryEntry) {
        val entry = activeHistoryEntry ?: return
        val updated = transform(entry)
        activeHistoryEntry = updated
        historyStore.save(updated)
        publishHistory(updated)
    }

    private fun updateHistoryLog() =
        updateHistory { it.copy(log = mutableState.value.log) }

    private fun updateHistoryProfile(profileId: String) =
        updateHistory { it.copy(profileId = profileId) }

    private fun finishHistory(result: InstallRunResult) {
        updateHistory { entry ->
            entry.copy(
                completedAtMillis = System.currentTimeMillis(),
                result = result,
                log = mutableState.value.log,
            )
        }
        activeHistoryEntry = null
    }

    private fun publishHistory(entry: InstallHistoryEntry) {
        mutableHistory.value = (mutableHistory.value.filterNot { it.id == entry.id } + entry)
            .sortedByDescending(InstallHistoryEntry::startedAtMillis)
    }

    private fun File.readTextIfPresent(): String = if (exists()) readText() else ""

    companion object {
        private const val EXPLOIT_ATTEMPTS = "8"
        private const val P0_ATTEMPT_TIMEOUT_SEC = "45"
        private const val EXPLOIT_ATTEMPT_TIMEOUT_SEC = "120"
        private const val EXPLOIT_STALL_MILLIS = 90_000L
        private const val EXPLOIT_TOTAL_MILLIS = 900_000L
        private const val HELPER_TIMEOUT_MILLIS = 120_000L
        private const val INSTALL_RECEIPT = "install_receipt"
        private const val RECEIPT_BOOT_TOKEN = "kernel_boot_id"
        private const val RECEIPT_VERIFIED = "verified"
        private const val P0_CACHE = "p0_cache"
        private const val P0_CACHE_BOOT_TOKEN = "kernel_boot_id"
        private const val P0_CACHE_OFFSET = "offset"
        private const val P0_OFFSET_ENV = "SLIDE_P0_OFFSET"
        private const val P0_OFFSET_MAX = 0x1f0000L
        private const val P0_OFFSET_MASK = 0xffffL
        private const val SHIZUKU_LOG_PATH = "/data/local/tmp/ksu-exploit.log"
        private const val SHIZUKU_HELPER_PATH = "/data/local/tmp/ksu-helper"
        private const val SHIZUKU_PAYLOAD_PATH = "/data/local/tmp/ksu-payload"
        // Must match ROOT_UMH_PATH in the payload's target.h: the payload's
        // workqueue root stage execs this exact path with --umh.
        private const val SHIZUKU_ROOT_CLIENT_PATH = "/data/local/tmp/cve-2026-43499-root"
        private const val SHIZUKU_KSULOAD_PATH = "/data/local/tmp/ksu-load.so"
        private const val SHIZUKU_KSU_KO_PATH = "/data/local/tmp/ksu-c12.ko"
        private const val KSU_LOAD_OK_MARKER = "KernelSU loaded OK"
        private val LOG_POLL_INTERVAL = 250.milliseconds
        private val HELPER_POLL_INTERVAL = 250.milliseconds
        private val SHIZUKU_LOG_POLL_INTERVAL = 1.seconds
        private val ANSI_ESCAPE = Regex("\u001B\\[[0-?]*[ -/]*[@-~]")
        private val P0_OFFSET_PATTERN = Regex(
            "slide-kaslr-ok[^\\n]*slide=([0-9a-fA-F]{16})",
        )

        private fun stripAnsi(value: String): String = ANSI_ESCAPE.replace(value, "").replace("\r", "")
    }
}
