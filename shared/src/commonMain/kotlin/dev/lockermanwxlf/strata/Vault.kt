package dev.lockermanwxlf.strata

/**
 * The vault API that common (UI) code sees. Platform code implements it on top of the
 * Rust core's generated bindings.
 *
 * Secrets:
 * - Every `ByteArray` argument (passwords, recovery words, field values) is **wiped**
 *   (filled with zeros) once the core has its copy, so callers can't forget to.
 * - Every `ByteArray` returned holds a secret. Wipe it with [wipe] as soon as it has
 *   been shown or copied.
 * - Secrets never appear as `String`: summaries and details carry only non-secret
 *   values, and secret fields are revealed one at a time with [VaultHandle.reveal].
 *
 * Suspending calls run on a background dispatcher: unlocking runs Argon2, and
 * syncing reads and writes the vault folder.
 */
interface VaultHandle {
    /** Answers at once, even while another call is running. */
    val isLocked: Boolean

    /** Unlocks with the password (UTF-8 bytes), then syncs. */
    suspend fun unlockPassword(password: ByteArray): SyncSummary

    /** Unlocks with the 24 recovery words as typed (UTF-8 bytes), then syncs. */
    suspend fun unlockRecovery(words: ByteArray): SyncSummary

    /**
     * Forgets every key and decrypted value. [isLocked] turns true at once; the keys
     * go as soon as a call in progress (say a sync) finishes.
     */
    suspend fun lock()

    suspend fun sync(): SyncSummary
    suspend fun status(): VaultStatus

    /** Every entry, trash included. */
    suspend fun entries(): List<EntrySummary>
    suspend fun entry(entryId: String): EntryDetail

    /** One field's value. Wipe the result when done. */
    suspend fun reveal(entryId: String, field: String): ByteArray

    /** Every value of a field in conflict. Wipe the values when done. */
    suspend fun revealConflict(entryId: String, field: String): List<ConflictCandidate>

    /** Applies the edits as one change. Field values in the edits are wiped. */
    suspend fun apply(edits: List<EntryEdit>)

    suspend fun devices(): List<DeviceInfo>
    suspend fun renameDevice(name: String)
    suspend fun changePassword(newPassword: ByteArray): RotationSummary

    /** Returns the new recovery words; the old ones stop working. Wipe them when shown. */
    suspend fun replaceRecoveryKey(password: ByteArray): ByteArray
    suspend fun revokeDevice(clientId: String, password: ByteArray): RotationSummary

    /** After [SyncSummary.lostRotation]: switch to the winning device's key. */
    suspend fun rejoinPassword(password: ByteArray)
    suspend fun rejoinRecovery(words: ByteArray)

    /** Removes an entry for good. Rotates the key. */
    suspend fun purge(entryId: String, password: ByteArray): PurgeSummary

    /** Reverts every change flagged for review; returns how many edits that took. */
    suspend fun revertFlagged(): Int

    /**
     * Imports a KeePass file as new entries. [password] (UTF-8, may be empty) and
     * [keyfile] are wiped; [file] is the encrypted file and isn't.
     */
    suspend fun importKdbx(file: ByteArray, password: ByteArray, keyfile: ByteArray?): ImportSummary

    /** Every entry not in the trash, as a KeePass file under [password] (wiped). Not protected by Strata. */
    suspend fun exportKdbx(password: ByteArray): ExportedFile

    /** The protector IDs with a local slot that can unlock this device. Works while locked. */
    suspend fun localUnlocks(): List<Int>

    /**
     * Unlocks with [protector] (biometrics, Windows Hello), then syncs. Throws
     * [StrataException.Reason.KEY_INVALIDATED] if the platform key is gone: unlock
     * with the password instead, which also removes the dead slot.
     */
    suspend fun unlockLocal(protector: DeviceProtector, pin: ByteArray? = null): SyncSummary

    /**
     * Lets [protector] unlock this device from now on. Prompts once, or takes [pin]
     * when [DeviceProtector.needsPin]. The PIN is wiped.
     */
    suspend fun enableLocalUnlock(protector: DeviceProtector, pin: ByteArray? = null)

    suspend fun disableLocalUnlock(protectorId: Int)

    /** Locks and releases the native handle. The handle can't be used afterwards. */
    fun close()
}

/** Entry points into the core. */
object StrataCore {
    /** Version of the native library, which also confirms it loaded. */
    fun version(): String = nativeVersion()

    /** Creates a vault in the empty folder [vaultDir] and returns it unlocked. */
    suspend fun createVault(
        vaultDir: String,
        stateDir: String,
        password: ByteArray,
        deviceName: String,
    ): CreatedVault = nativeCreateVault(vaultDir, stateDir, password, deviceName)

    /**
     * A locked handle on an existing vault. [stateDir] holds this device's local
     * state; [deviceName] is used if this device joins the vault.
     */
    fun openVault(vaultDir: String, stateDir: String, deviceName: String): VaultHandle =
        nativeOpenVault(vaultDir, stateDir, deviceName)

    /** [createVault] in a folder the platform reaches through its own API. */
    suspend fun createVault(
        folder: VaultFolder,
        stateDir: String,
        password: ByteArray,
        deviceName: String,
    ): CreatedVault = nativeCreateVaultIn(folder, stateDir, password, deviceName)

    /** [openVault] for a folder the platform reaches through its own API. */
    fun openVault(folder: VaultFolder, stateDir: String, deviceName: String): VaultHandle =
        nativeOpenVaultIn(folder, stateDir, deviceName)

    /** The weak-password estimate. Advisory: any password is allowed. */
    suspend fun passwordStrength(password: ByteArray): StrengthEstimate = nativePasswordStrength(password)

    fun newEntryId(): String = nativeNewEntryId()

    /** A random password: letters and digits, plus symbols if asked. Wipe it when used. */
    fun generatePassword(length: Int, symbols: Boolean): ByteArray = nativeGeneratePassword(length, symbols)

    /** The usual folder for this device's local state on desktop systems. */
    fun defaultStateDir(): String? = nativeDefaultStateDir()

    /**
     * This computer's device unlock, if it has one: Windows Hello, the macOS Secure
     * Enclave, or on Linux the TPM (with a PIN) or else the desktop keyring.
     */
    fun desktopProtector(): DeviceProtector? = nativeDesktopProtector()
}

/**
 * A platform protector that can unlock this device: biometrics, Windows Hello. The
 * core talks to it; common code only passes it along. IDs follow spec §11.
 */
interface DeviceProtector {
    val id: Int

    /** What the UI calls it: "Windows Hello", "fingerprint or screen lock". */
    val label: String

    /**
     * The app asks for a PIN itself and passes it with each call (the Linux TPM).
     * Other protectors show the platform's own prompt.
     */
    val needsPin: Boolean get() = false

    companion object {
        const val ANDROID_KEYSTORE = 1
        const val WINDOWS_HELLO = 2
        const val SECURE_ENCLAVE = 3
        const val TPM = 4
        const val SECRET_SERVICE = 5
    }
}

/**
 * A vault folder the platform reaches through its own API instead of a path: on
 * Android, a folder picked through the Storage Access Framework. Paths are relative to
 * the vault: `strata-vault`, or `<dir>/<name>` in one of the vault's directories.
 *
 * The core checks every path before calling, and checks names and sizes again on what
 * comes back, so an implementation only moves bytes. Calls come from a background
 * thread. Failures other than a [VaultFolderException] reach the user as storage errors.
 */
interface VaultFolder {
    /** The names of the files directly in [dir] (`""` is the vault root); empty if it doesn't exist. */
    fun list(dir: String): List<String>

    /** The file's bytes. [VaultFolderException.Kind.TOO_LARGE] past [maxLen] bytes, without reading them all. */
    fun read(path: String, maxLen: Long): ByteArray

    /**
     * Creates the file, and its directory if needed. [VaultFolderException.Kind.ALREADY_EXISTS]
     * if the name is taken: never overwrite, never settle for another name, and never
     * leave a second file with the same name.
     */
    fun create(path: String, bytes: ByteArray)

    fun delete(path: String)
}

class VaultFolderException(val kind: Kind, message: String) : Exception(message) {
    enum class Kind { ALREADY_EXISTS, NOT_FOUND, TOO_LARGE }
}

// Implemented per platform on top of the generated bindings (NativeVault.kt).
internal expect fun nativeVersion(): String

internal expect suspend fun nativeCreateVaultIn(
    folder: VaultFolder,
    stateDir: String,
    password: ByteArray,
    deviceName: String,
): CreatedVault

internal expect fun nativeOpenVaultIn(folder: VaultFolder, stateDir: String, deviceName: String): VaultHandle

internal expect suspend fun nativeCreateVault(
    vaultDir: String,
    stateDir: String,
    password: ByteArray,
    deviceName: String,
): CreatedVault

internal expect fun nativeOpenVault(vaultDir: String, stateDir: String, deviceName: String): VaultHandle

internal expect suspend fun nativePasswordStrength(password: ByteArray): StrengthEstimate

internal expect fun nativeNewEntryId(): String

internal expect fun nativeGeneratePassword(length: Int, symbols: Boolean): ByteArray

internal expect fun nativeDefaultStateDir(): String?

internal expect fun nativeDesktopProtector(): DeviceProtector?

/** Overwrites the array with zeros. */
fun ByteArray.wipe() = fill(0)

/** A new vault, unlocked, and its recovery words: show them once, then wipe them. */
class CreatedVault(val vault: VaultHandle, val recoveryWords: ByteArray)

enum class Alarm { ROLLBACK, FORK, SLOT_SUBSTITUTION, FORGERY }

data class SyncSummary(
    val applied: Int,
    val uploaded: Int,
    val held: Int,
    val rejected: Int,
    val farFuture: Int,
    /** Another device changed the key: read-only until the next unlock. */
    val keyRotated: Boolean,
    /** Another device's concurrent key change won: read-only until a rejoin. */
    val lostRotation: Boolean,
    val identityReset: Boolean,
    val integrityUnverified: Boolean,
    val snapshotWritten: Boolean,
    val filesDeleted: Int,
    /** Alarms are state, not exceptions: the vault stays open to read. */
    val alarm: Alarm?,
)

data class VaultStatus(
    val locked: Boolean,
    val alarm: Alarm?,
    val keyRotated: Boolean,
    val lostRotation: Boolean,
    val conflicts: Int,
    val unansweredDeletes: Int,
    val flaggedChanges: Int,
    val suspectDevices: Int,
)

/** One line of the entry list. Holds no secret values. */
data class EntrySummary(
    val id: String,
    val title: String?,
    val username: String?,
    val tags: List<String>,
    val deleted: Boolean,
    val hasConflict: Boolean,
    val unansweredDelete: Boolean,
)

data class EntryDetail(
    val id: String,
    val fields: List<FieldInfo>,
    val tags: List<String>,
    val deleted: Boolean,
    val unansweredDelete: Boolean,
)

data class FieldInfo(
    val name: String,
    val secret: Boolean,
    /** Set only for non-secret fields. Secret ones go through [VaultHandle.reveal]. */
    val value: String?,
    /** Concurrent values the field holds; 0 when there's no conflict. */
    val conflictCandidates: Int,
)

/** One side of a conflict. [value] is a secret (or `null`: deleted on that side). */
class ConflictCandidate(val value: ByteArray?, val deviceId: String, val deviceName: String?)

data class DeviceInfo(
    val clientId: String,
    val name: String,
    val thisDevice: Boolean,
    val retired: Boolean,
    val suspect: Boolean,
)

data class RotationSummary(val epoch: Int, val recoveryLost: Boolean)

data class PurgeSummary(
    val rotation: RotationSummary,
    val eventsDeleted: Int,
    val snapshotsDeleted: Int,
    val eventsLeft: Int,
    val snapshotsLeft: Int,
)

data class StrengthEstimate(val guessesLog10: Double, val warn: Boolean)

/** What a KeePass import added and left out. */
data class ImportSummary(
    val entries: Int,
    /** In the KeePass recycle bin. */
    val recycled: Int,
    /** Older versions of entries: Strata keeps no field history. */
    val history: Int,
    /** Fields, attachments and tags over the vault's limits. */
    val skipped: Int,
    val customIcons: Int,
)

/** A KeePass file made from the vault: encrypted, but not by Strata. */
class ExportedFile(val bytes: ByteArray, val entries: Int, val conflicts: Int, val skipped: Int)

sealed class EntryEdit {
    /** Sets a field, or removes it with a `null` value. The value is wiped once applied. */
    class SetField(
        val entryId: String,
        val name: String,
        val value: ByteArray?,
        val secret: Boolean = false,
    ) : EntryEdit()

    class DeleteEntry(val entryId: String) : EntryEdit()

    /** "Keep" after a delete on another device; also restores from the trash. */
    class KeepEntry(val entryId: String) : EntryEdit()

    class AddTag(val entryId: String, val tag: String) : EntryEdit()
    class RemoveTag(val entryId: String, val tag: String) : EntryEdit()
}

/** A failed call. [alarm] is set when [reason] is [Reason.ALARM]. */
class StrataException(val reason: Reason, message: String, val alarm: Alarm? = null) :
    Exception(message) {
    enum class Reason {
        REJECTED,
        ALARM,
        UPDATE_REQUIRED,
        LOCKED,
        KEY_ROTATED,
        CONFLICTING_ROTATION,
        WRONG_CREDENTIAL,
        RECOVERY_WORDS,
        POLICY,
        RNG,
        IO,
        NOT_FOUND,
        FIELD_CONFLICT,

        /** The user dismissed the device-unlock prompt. */
        CANCELLED,

        /** The device-unlock key is gone (say, fingerprints changed): use the password. */
        KEY_INVALIDATED,
        PROTECTOR_UNAVAILABLE,

        /** A KeePass file that couldn't be opened or written. */
        KEEPASS,
    }
}
