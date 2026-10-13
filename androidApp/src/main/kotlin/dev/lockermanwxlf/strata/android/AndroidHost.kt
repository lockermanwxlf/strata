package dev.lockermanwxlf.strata.android

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.provider.Settings
import android.view.WindowManager
import dev.lockermanwxlf.strata.AppHost
import dev.lockermanwxlf.strata.DeviceProtector
import dev.lockermanwxlf.strata.deviceProtector
import dev.lockermanwxlf.strata.SecretClipboard
import java.io.File
import java.nio.ByteBuffer

class AndroidHost(private val activity: Activity) : AppHost {
    override val stateDir: String = File(activity.filesDir, "state").path

    override val defaultDeviceName: String =
        Settings.Global.getString(activity.contentResolver, Settings.Global.DEVICE_NAME) ?: Build.MODEL

    private val prefs = activity.getSharedPreferences("ui", Context.MODE_PRIVATE)

    override var lastVaultFolder: String?
        get() = prefs.getString("lastVaultFolder", null)
        set(value) = prefs.edit().putString("lastVaultFolder", value).apply()

    /**
     * The app's own folder until folders from the Storage Access Framework are
     * supported. App-specific external storage, so the files can be copied off the
     * device; they're encrypted either way.
     */
    private val vaultFolder: File = File(activity.getExternalFilesDir(null) ?: activity.filesDir, "vault")

    override suspend fun chooseVaultFolder(forNewVault: Boolean): String {
        vaultFolder.mkdirs()
        return vaultFolder.path
    }

    override fun isVault(folder: String): Boolean = File(folder, "strata-vault").isFile

    /** Biometrics or the screen lock, through Android Keystore; none without a screen lock. */
    override val deviceProtector: DeviceProtector? = KeystoreProtector(activity)
        .takeIf { it.available }
        ?.let { deviceProtector(DeviceProtector.ANDROID_KEYSTORE, "fingerprint or screen lock", it) }

    override val clipboard: SecretClipboard = AndroidClipboard(activity)

    override fun setSecureScreen(secure: Boolean) {
        // Release builds keep FLAG_SECURE on all the time (MainActivity).
        if (!BuildConfig.ALLOW_SCREENSHOTS) return
        if (secure) {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

private class AndroidClipboard(context: Context) : SecretClipboard {
    private val manager = context.getSystemService(ClipboardManager::class.java)

    override fun copy(value: ByteArray) {
        // ClipData takes a CharSequence: decoded straight into a char buffer, which is
        // wiped after handing it over. The clipboard service keeps its own copy.
        val chars = Charsets.UTF_8.decode(ByteBuffer.wrap(value))
        value.fill(0)
        val clip = ClipData.newPlainText(LABEL, chars)
        // Hides the preview in the system's copy confirmation (Android 13+).
        clip.description.extras = PersistableBundle().apply {
            putBoolean(
                if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE",
                true,
            )
        }
        manager.setPrimaryClip(clip)
        if (chars.hasArray()) chars.array().fill('\u0000')
    }

    override fun clearIfStillOurs() {
        // The description is readable while the app is in front. When it isn't, clear anyway.
        val label = runCatching { manager.primaryClipDescription?.label }.getOrNull()
        if (label == null || label == LABEL) manager.clearPrimaryClip()
    }

    private companion object {
        const val LABEL = "Strata"
    }
}
