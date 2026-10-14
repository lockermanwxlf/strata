package dev.lockermanwxlf.strata

/**
 * What the shared UI needs from the platform: where things live, the clipboard, and
 * window-level protection. Desktop and Android each implement it in their app module.
 */
interface AppHost {
    /** Folder for this device's local state. Private to the app; never synced. */
    val stateDir: String

    /** A name for this device in the vault's device list, e.g. the computer's name. */
    val defaultDeviceName: String

    /** The vault folder used last time, remembered between runs. Not secret. */
    var lastVaultFolder: String?

    /**
     * Asks where the vault is, or where a new one goes; `null` if the user cancelled.
     * The answer is a path on desktop and a folder URI on Android.
     */
    suspend fun chooseVaultFolder(forNewVault: Boolean): String?

    /** Whether [folder] holds a vault (its `strata-vault` file). */
    suspend fun isVault(folder: String): Boolean

    /**
     * How the core reaches [folder]: `null` for a filesystem path, otherwise the
     * platform's own access to it (on Android, the Storage Access Framework).
     */
    fun platformFolder(folder: String): VaultFolder? = null

    /** [folder] as the user should see it. */
    suspend fun describeFolder(folder: String): String = folder

    /** Asks for a file to read (a KeePass file, a key file); `null` if the user cancelled. */
    suspend fun openFile(): PickedFile?

    /** Asks where to save [bytes], suggesting [name]; `false` if the user cancelled. */
    suspend fun saveFile(name: String, bytes: ByteArray): Boolean

    /** Biometric or Windows Hello unlock on this device, or `null` if there is none. */
    val deviceProtector: DeviceProtector?

    val clipboard: SecretClipboard

    /**
     * Keeps the window out of screenshots and the app switcher while [secure] is true.
     * Android only; release builds are always secure. Used for the recovery words.
     */
    fun setSecureScreen(secure: Boolean)
}

/** A file the user picked: its name, for display, and its contents. */
class PickedFile(val name: String, val bytes: ByteArray)

/**
 * The clipboard, for secrets. This is one of the two places a secret becomes a
 * platform string (the other is drawing it on screen), because clipboard APIs take
 * nothing else.
 */
interface SecretClipboard {
    /** Copies [value] (UTF-8), marked sensitive where the platform supports it, then wipes it. */
    fun copy(value: ByteArray)

    /** Clears the clipboard, unless something else has been copied since [copy]. */
    fun clearIfStillOurs()
}
