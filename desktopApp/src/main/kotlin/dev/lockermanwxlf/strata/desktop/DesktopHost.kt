package dev.lockermanwxlf.strata.desktop

import dev.lockermanwxlf.strata.AppHost
import dev.lockermanwxlf.strata.SecretClipboard
import dev.lockermanwxlf.strata.StrataCore
import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.ClipboardOwner
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.awt.datatransfer.SystemFlavorMap
import java.awt.datatransfer.Transferable
import java.awt.datatransfer.UnsupportedFlavorException
import java.io.ByteArrayInputStream
import java.io.File
import java.net.InetAddress
import java.util.Properties
import javax.swing.JFileChooser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext

class DesktopHost : AppHost {
    override val stateDir: String =
        StrataCore.defaultStateDir() ?: File(System.getProperty("user.home"), ".strata").path

    override val defaultDeviceName: String =
        System.getenv("COMPUTERNAME")
            ?: System.getenv("HOSTNAME")
            ?: runCatching { InetAddress.getLocalHost().hostName }.getOrNull()
            ?: "Computer"

    /** Remembered UI settings, next to the local state. Nothing secret goes here. */
    private val settingsFile = File(stateDir, "ui.properties")
    private val settings = Properties().apply {
        runCatching { settingsFile.inputStream().use(::load) }
    }

    override var lastVaultFolder: String?
        get() = settings.getProperty("lastVaultFolder")
        set(value) {
            if (value == null) settings.remove("lastVaultFolder") else settings.setProperty("lastVaultFolder", value)
            runCatching {
                settingsFile.parentFile.mkdirs()
                settingsFile.outputStream().use { settings.store(it, "Strata") }
            }
        }

    override suspend fun chooseVaultFolder(forNewVault: Boolean): String? = withContext(Dispatchers.Swing) {
        val chooser = JFileChooser(lastVaultFolder?.let { File(it).parentFile }).apply {
            fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            dialogTitle = if (forNewVault) "Choose an empty folder for the new vault" else "Choose the vault folder"
        }
        if (chooser.showDialog(null, "Choose") == JFileChooser.APPROVE_OPTION) chooser.selectedFile.path else null
    }

    override fun isVault(folder: String): Boolean = File(folder, "strata-vault").isFile

    override val clipboard: SecretClipboard = AwtClipboard()

    /** Desktop windows have no equivalent of Android's FLAG_SECURE wired up yet. */
    override fun setSecureScreen(secure: Boolean) = Unit
}

/**
 * The system clipboard. AWT only takes text as a `String`, so the secret becomes one
 * here; it's made only when something pastes, and dropped when the clipboard is cleared.
 */
internal class AwtClipboard : SecretClipboard {
    private val system: Clipboard = Toolkit.getDefaultToolkit().systemClipboard

    @Volatile
    private var current: SecretSelection? = null

    override fun copy(value: ByteArray) {
        val selection = SecretSelection(value.copyOf())
        value.fill(0)
        current?.wipe()
        current = selection
        system.setContents(selection, selection)
    }

    override fun clearIfStillOurs() {
        val ours = current ?: return
        current = null
        ours.wipe()
        // Lost ownership means something else was copied since; leave that alone.
        if (!ours.lost) system.setContents(StringSelection(""), null)
    }
}

/**
 * Windows clipboard formats that keep a copied secret out of clipboard history (Win+V),
 * the cloud clipboard and clipboard monitors. Their presence (or a zero DWORD) is the
 * signal; AWT publishes each under its native name. Empty on other systems.
 */
private object WindowsClipboardHints {
    private val zeroDword = ByteArray(4)

    val formats: Map<DataFlavor, ByteArray> =
        if (!System.getProperty("os.name").startsWith("Windows")) {
            emptyMap()
        } else {
            val map = SystemFlavorMap.getDefaultFlavorMap() as SystemFlavorMap
            listOf(
                "ExcludeClipboardContentFromMonitorProcessing",
                "CanIncludeInClipboardHistory",
                "CanUploadToCloudClipboard",
            ).associate { native ->
                val flavor = DataFlavor("application/x-strata-${native.lowercase()};class=java.io.InputStream", native)
                map.addUnencodedNativeForFlavor(flavor, native)
                map.addFlavorForUnencodedNative(native, flavor)
                flavor to zeroDword
            }
        }
}

internal class SecretSelection(private val bytes: ByteArray) : Transferable, ClipboardOwner {
    @Volatile
    var lost = false
        private set

    override fun getTransferDataFlavors(): Array<DataFlavor> =
        arrayOf(DataFlavor.stringFlavor) + WindowsClipboardHints.formats.keys

    override fun isDataFlavorSupported(flavor: DataFlavor) =
        flavor == DataFlavor.stringFlavor || flavor in WindowsClipboardHints.formats

    override fun getTransferData(flavor: DataFlavor): Any {
        WindowsClipboardHints.formats[flavor]?.let { return ByteArrayInputStream(it) }
        if (flavor != DataFlavor.stringFlavor) throw UnsupportedFlavorException(flavor)
        return bytes.decodeToString()
    }

    override fun lostOwnership(clipboard: Clipboard, contents: Transferable) {
        lost = true
        wipe()
    }

    fun wipe() = bytes.fill(0)
}
