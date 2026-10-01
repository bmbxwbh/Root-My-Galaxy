package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.File
import java.io.FileOutputStream

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

/**
 * Local-variant payload repository: the support manifest and every artifact
 * ship inside the APK under `assets/`, so target discovery, download and
 * verification run fully offline.
 *
 * Manifest entries reference artifacts with an `asset:` prefix instead of an
 * http(s) URL; [download] stages them into `filesDir/payloads/<profileId>/`
 * with the same exact-size verification the network path used.
 */
class PayloadRepository(private val context: Context) {
    fun loadTargets(): List<TargetProfile> {
        val manifestBytes = readAsset(MANIFEST_ASSET, MAX_MANIFEST_BYTES)
        return SupportManifest.parse(manifestBytes).targets
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = loadTargets()
        .firstOrNull { it.matches(snapshot) }
        ?: error(context.getString(R.string.repo_no_profile))

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = stageAsset(
            profile.exploit,
            File(directory, "cve-2026-43499-app.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = stageAsset(
            profile.kernelSu,
            File(directory, "ksud-s25u-kdp"),
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    private fun stageAsset(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        require(artifact.url.startsWith(ASSET_PREFIX)) {
            context.getString(R.string.repo_url_invalid)
        }
        val assetPath = artifact.url.removePrefix(ASSET_PREFIX)
        val temporary = File(destination.parentFile, "${destination.name}.part")
        var total = 0L
        context.assets.open(assetPath).use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun readAsset(path: String, maximum: Int): ByteArray {
        val bytes = context.assets.open(path).use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        return bytes
    }

    companion object {
        private const val MANIFEST_ASSET = "support/targets-v3.json"
        private const val ASSET_PREFIX = "asset:"
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}
