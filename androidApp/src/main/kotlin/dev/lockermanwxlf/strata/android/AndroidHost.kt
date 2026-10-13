package dev.lockermanwxlf.strata.android

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PersistableBundle
import android.provider.DocumentsContract
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import dev.lockermanwxlf.strata.AppHost
import dev.lockermanwxlf.strata.DeviceProtector
import dev.lockermanwxlf.strata.deviceProtector
import dev.lockermanwxlf.strata.SecretClipboard
import dev.lockermanwxlf.strata.StrataException
import java.io.File
import java.nio.ByteBuffer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val READ_WRITE = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION

/** The authority of the device's own storage in the Storage Access Framework. */
private const val EXTERNAL_STORAGE = "com.android.externalstorage.documents"

class AndroidHost(private val activity: ComponentActivity) : AppHost {
    override val stateDir: String = File(activity.filesDir, "state").path

    override val defaultDeviceName: String =
        Settings.Global.getString(activity.contentResolver, Settings.Global.DEVICE_NAME) ?: Build.MODEL

    private val prefs = activity.getSharedPreferences("ui", Context.MODE_PRIVATE)

    private val resolver = activity.contentResolver

    /**
     * Also gives up access to every other folder picked earlier: the app keeps one
     * vault, and Android limits how many folders an app may hold on to.
     */
    override var lastVaultFolder: String?
        get() = prefs.getString("lastVaultFolder", null)
        set(value) {
            prefs.edit().putString("lastVaultFolder", value).apply()
            resolver.persistedUriPermissions
                .filter { it.uri.toString() != value }
                .forEach { runCatching { resolver.releasePersistableUriPermission(it.uri, READ_WRITE) } }
        }

    private var picked: CompletableDeferred<Uri?>? = null

    // Registered while the activity is created, as the Activity Result API requires.
    private val folderPicker = activity.registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) {
        picked?.complete(it)
    }

    /**
     * The system folder picker (Storage Access Framework). A folder on the device that
     * another app syncs (Syncthing and the like), or a cloud provider's folder.
     */
    override suspend fun chooseVaultFolder(forNewVault: Boolean): String? {
        val result = CompletableDeferred<Uri?>()
        picked?.cancel()
        picked = result
        folderPicker.launch(null)
        val uri = result.await() ?: return null
        try {
            resolver.takePersistableUriPermission(uri, READ_WRITE)
        } catch (e: SecurityException) {
            throw StrataException(StrataException.Reason.IO, "Strata can't keep access to that folder: ${e.message}")
        }
        return uri.toString()
    }

    override suspend fun isVault(folder: String): Boolean = withContext(Dispatchers.IO) {
        platformFolder(folder)?.holdsVault() ?: File(folder, "strata-vault").isFile
    }

    /**
     * Folders from the picker are content URIs. A plain path is a vault an earlier
     * version kept in the app's own storage.
     */
    override fun platformFolder(folder: String): SafFolder? =
        if (folder.startsWith("content://")) SafFolder(resolver, Uri.parse(folder)) else null

    private val labels = java.util.concurrent.ConcurrentHashMap<String, String>()

    override suspend fun describeFolder(folder: String): String = withContext(Dispatchers.IO) {
        if (!folder.startsWith("content://")) return@withContext folder
        labels.getOrPut(folder) {
            val tree = Uri.parse(folder)
            val id = DocumentsContract.getTreeDocumentId(tree)
            if (tree.authority == EXTERNAL_STORAGE) {
                // The device's storage names documents by path: "primary:Documents/Vault".
                id.substringAfter(':').ifEmpty { "Internal storage" }
            } else {
                runCatching {
                    val doc = DocumentsContract.buildDocumentUriUsingTree(tree, id)
                    resolver.query(doc, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)
                        ?.use { if (it.moveToFirst()) it.getString(0) else null }
                }.getOrNull() ?: id
            }
        }
    }

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
