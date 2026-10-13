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
     * Android has a fixed app folder for now and returns it without asking.
     */
    suspend fun chooseVaultFolder(forNewVault: Boolean): String?

    /** Whether [folder] holds a vault (its `strata-vault` file). */
    fun isVault(folder: String): Boolean

    /** Biometric or Windows Hello unlock on this device, or `null` if there is none. */
    val deviceProtector: DeviceProtector?

    val clipboard: SecretClipboard

    /**
     * Keeps the window out of screenshots and the app switcher while [secure] is true.
     * Android only; release builds are always secure. Used for the recovery words.
     */
    fun setSecureScreen(secure: Boolean)
}

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
