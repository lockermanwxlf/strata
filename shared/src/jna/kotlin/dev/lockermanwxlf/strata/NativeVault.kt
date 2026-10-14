package dev.lockermanwxlf.strata

// The bindings use JNA, so this file compiles separately for each JVM-based target
// (desktop and Android) from this one source directory, like the bindings themselves.
// It maps the generated API onto the common one in Vault.kt.

import dev.lockermanwxlf.strata.StrataException.Reason
import dev.lockermanwxlf.strata.core.ffi.AlarmKind
import dev.lockermanwxlf.strata.core.ffi.FolderException
import dev.lockermanwxlf.strata.core.ffi.ForeignFolder
import dev.lockermanwxlf.strata.core.ffi.PlatformProtector
import dev.lockermanwxlf.strata.core.ffi.Vault
import dev.lockermanwxlf.strata.core.ffi.VaultException
import dev.lockermanwxlf.strata.core.ffi.coreVersion
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import dev.lockermanwxlf.strata.core.ffi.EntryEdit as FfiEntryEdit
import dev.lockermanwxlf.strata.core.ffi.RotationSummary as FfiRotationSummary
import dev.lockermanwxlf.strata.core.ffi.SyncSummary as FfiSyncSummary
import dev.lockermanwxlf.strata.core.ffi.createVault as ffiCreateVault
import dev.lockermanwxlf.strata.core.ffi.createVaultInFolder as ffiCreateVaultInFolder
import dev.lockermanwxlf.strata.core.ffi.defaultStateDir as ffiDefaultStateDir
import dev.lockermanwxlf.strata.core.ffi.generatePassword as ffiGeneratePassword
import dev.lockermanwxlf.strata.core.ffi.newEntryId as ffiNewEntryId
import dev.lockermanwxlf.strata.core.ffi.passwordStrength as ffiPasswordStrength
import dev.lockermanwxlf.strata.core.ffi.linuxSecretService as ffiLinuxSecretService
import dev.lockermanwxlf.strata.core.ffi.linuxTpm as ffiLinuxTpm
import dev.lockermanwxlf.strata.core.ffi.linuxTpmAvailable as ffiLinuxTpmAvailable
import dev.lockermanwxlf.strata.core.ffi.secureEnclave as ffiSecureEnclave
import dev.lockermanwxlf.strata.core.ffi.windowsHello as ffiWindowsHello

internal actual fun nativeVersion(): String = coreVersion()

internal actual suspend fun nativeCreateVault(
    vaultDir: String,
    stateDir: String,
    password: ByteArray,
    deviceName: String,
): CreatedVault = background {
    consuming(password) {
        val created = ffiCreateVault(vaultDir, stateDir, password, deviceName)
        CreatedVault(NativeVault(created.vault), created.recoveryWords)
    }
}

internal actual fun nativeOpenVault(vaultDir: String, stateDir: String, deviceName: String): VaultHandle =
    mapped { NativeVault(Vault.open(vaultDir, stateDir, deviceName)) }

internal actual suspend fun nativeCreateVaultIn(
    folder: VaultFolder,
    stateDir: String,
    password: ByteArray,
    deviceName: String,
): CreatedVault = background {
    consuming(password) {
        val created = ffiCreateVaultInFolder(NativeFolder(folder), stateDir, password, deviceName)
        CreatedVault(NativeVault(created.vault), created.recoveryWords)
    }
}

internal actual fun nativeOpenVaultIn(folder: VaultFolder, stateDir: String, deviceName: String): VaultHandle =
    mapped { NativeVault(Vault.openFolder(NativeFolder(folder), stateDir, deviceName)) }

/** Hands a platform folder to the core, with its failures as the core expects them. */
private class NativeFolder(private val folder: VaultFolder) : ForeignFolder {
    override fun list(dir: String): List<String> = reported { folder.list(dir) }

    override fun read(path: String, maxLen: ULong): ByteArray =
        reported { folder.read(path, maxLen.coerceAtMost(Long.MAX_VALUE.toULong()).toLong()) }

    override fun create(path: String, bytes: ByteArray) = reported { folder.create(path, bytes) }

    override fun delete(path: String) = reported { folder.delete(path) }

    private inline fun <T> reported(block: () -> T): T =
        try {
            block()
        } catch (e: VaultFolderException) {
            throw when (e.kind) {
                VaultFolderException.Kind.ALREADY_EXISTS -> FolderException.AlreadyExists()
                VaultFolderException.Kind.NOT_FOUND -> FolderException.NotFound()
                VaultFolderException.Kind.TOO_LARGE -> FolderException.TooLarge()
            }
        } catch (e: Exception) {
            throw FolderException.Failed(e.message ?: e.javaClass.simpleName)
        }
}

internal actual suspend fun nativePasswordStrength(password: ByteArray): StrengthEstimate = background {
    consuming(password) {
        ffiPasswordStrength(password).let { StrengthEstimate(it.guessesLog10, it.warn) }
    }
}

internal actual fun nativeNewEntryId(): String = mapped { ffiNewEntryId() }

internal actual fun nativeGeneratePassword(length: Int, symbols: Boolean): ByteArray =
    mapped { ffiGeneratePassword(length.toUInt(), symbols) }

internal actual fun nativeDefaultStateDir(): String? = ffiDefaultStateDir()

internal actual fun nativeDesktopProtector(): DeviceProtector? =
    ffiWindowsHello()?.let { NativeProtector(DeviceProtector.WINDOWS_HELLO, "Windows Hello", it) }
        ?: ffiSecureEnclave()?.let { NativeProtector(DeviceProtector.SECURE_ENCLAVE, "Touch ID or your login password", it) }
        ?: if (ffiLinuxTpmAvailable()) {
            NativeProtector(DeviceProtector.TPM, "a TPM PIN", null) { pin -> ffiLinuxTpm(pin) }
        } else {
            ffiLinuxSecretService()?.let { NativeProtector(DeviceProtector.SECRET_SERVICE, "your desktop keyring", it) }
        }

/** Wraps a platform protector (Kotlin on Android, Rust on desktop) for common code. */
fun deviceProtector(id: Int, label: String, protector: PlatformProtector): DeviceProtector =
    NativeProtector(id, label, protector)

/** A protector, or for one that takes a PIN, the way to make one from it. */
private class NativeProtector(
    override val id: Int,
    override val label: String,
    private val protector: PlatformProtector?,
    private val withPin: ((ByteArray) -> PlatformProtector?)? = null,
) : DeviceProtector {
    override val needsPin: Boolean get() = withPin != null

    /** The protector for one call. A PIN is wiped once the core has its copy. */
    fun resolve(pin: ByteArray?): PlatformProtector {
        protector?.let { return it }
        val p = pin ?: throw StrataException(Reason.REJECTED, "a PIN is needed")
        return consuming(p) { withPin!!(p) }
            ?: throw StrataException(Reason.PROTECTOR_UNAVAILABLE, "device unlock unavailable: no TPM")
    }
}

private fun DeviceProtector.native(pin: ByteArray?): PlatformProtector =
    (this as? NativeProtector)?.resolve(pin) ?: error("not a protector from deviceProtector()")

private class NativeVault(private val vault: Vault) : VaultHandle {
    override val isLocked: Boolean
        get() = vault.isLocked()

    override suspend fun unlockPassword(password: ByteArray) = background {
        consuming(password) { vault.unlockPassword(password).common() }
    }

    override suspend fun unlockRecovery(words: ByteArray) = background {
        consuming(words) { vault.unlockRecovery(words).common() }
    }

    override suspend fun lock() = withContext(Dispatchers.IO) { vault.lock() }

    override suspend fun sync() = background { vault.sync().common() }

    override suspend fun status() = background {
        vault.status().let {
            VaultStatus(
                locked = it.locked,
                alarm = it.alarm?.common(),
                keyRotated = it.keyRotated,
                lostRotation = it.lostRotation,
                conflicts = it.conflicts.toInt(),
                unansweredDeletes = it.unansweredDeletes.toInt(),
                flaggedChanges = it.flaggedChanges.toInt(),
                suspectDevices = it.suspectDevices.toInt(),
            )
        }
    }

    override suspend fun entries() = background {
        vault.entries().map {
            EntrySummary(it.id, it.title, it.username, it.tags, it.deleted, it.hasConflict, it.unansweredDelete)
        }
    }

    override suspend fun entry(entryId: String) = background {
        vault.entry(entryId).let { detail ->
            EntryDetail(
                id = detail.id,
                fields = detail.fields.map {
                    FieldInfo(it.name, it.secret, it.value, it.conflictCandidates.toInt())
                },
                tags = detail.tags,
                deleted = detail.deleted,
                unansweredDelete = detail.unansweredDelete,
            )
        }
    }

    override suspend fun reveal(entryId: String, field: String) = background {
        vault.reveal(entryId, field)
    }

    override suspend fun revealConflict(entryId: String, field: String) = background {
        vault.revealConflict(entryId, field).map { ConflictCandidate(it.value, it.deviceId, it.deviceName) }
    }

    override suspend fun apply(edits: List<EntryEdit>) = background {
        try {
            vault.apply(edits.map { it.ffi() })
        } finally {
            edits.forEach { (it as? EntryEdit.SetField)?.value?.wipe() }
        }
    }

    override suspend fun devices() = background {
        vault.devices().map { DeviceInfo(it.clientId, it.name, it.thisDevice, it.retired, it.suspect) }
    }

    override suspend fun renameDevice(name: String) = background { vault.renameDevice(name) }

    override suspend fun changePassword(newPassword: ByteArray) = background {
        consuming(newPassword) { vault.changePassword(newPassword).common() }
    }

    override suspend fun replaceRecoveryKey(password: ByteArray) = background {
        consuming(password) { vault.replaceRecoveryKey(password) }
    }

    override suspend fun revokeDevice(clientId: String, password: ByteArray) = background {
        consuming(password) { vault.revokeDevice(clientId, password).common() }
    }

    override suspend fun rejoinPassword(password: ByteArray) = background {
        consuming(password) { vault.rejoinPassword(password) }
    }

    override suspend fun rejoinRecovery(words: ByteArray) = background {
        consuming(words) { vault.rejoinRecovery(words) }
    }

    override suspend fun purge(entryId: String, password: ByteArray) = background {
        consuming(password) {
            vault.purge(entryId, password).let {
                PurgeSummary(
                    rotation = it.rotation.common(),
                    eventsDeleted = it.eventsDeleted.toInt(),
                    snapshotsDeleted = it.snapshotsDeleted.toInt(),
                    eventsLeft = it.eventsLeft.toInt(),
                    snapshotsLeft = it.snapshotsLeft.toInt(),
                )
            }
        }
    }

    override suspend fun revertFlagged() = background { vault.revertFlagged().toInt() }

    override suspend fun importKdbx(file: ByteArray, password: ByteArray, keyfile: ByteArray?) = background {
        try {
            vault.importKdbx(file, password, keyfile).let {
                ImportSummary(
                    entries = it.entries.toInt(),
                    recycled = it.recycled.toInt(),
                    history = it.history.toInt(),
                    skipped = it.skipped.toInt(),
                    customIcons = it.customIcons.toInt(),
                )
            }
        } finally {
            password.wipe()
            keyfile?.wipe()
        }
    }

    override suspend fun restorableFiles() = background { vault.restorableFiles().toInt() }

    override suspend fun restoreFromCopy() = background {
        vault.restoreFromCopy().let { RestoreSummary(it.restored.toInt(), it.sync?.common()) }
    }

    override suspend fun startOver() = background { vault.startOverOnThisDevice() }

    override suspend fun exportKdbx(password: ByteArray) = background {
        consuming(password) {
            vault.exportKdbx(password).let {
                ExportedFile(it.bytes, it.entries.toInt(), it.conflicts.toInt(), it.skipped.toInt())
            }
        }
    }

    override suspend fun localUnlocks() = background { vault.localUnlocks().map { it.toInt() and 0xff } }

    override suspend fun unlockLocal(protector: DeviceProtector, pin: ByteArray?) = backgroundSuspend {
        vault.unlockLocal(protector.native(pin), protector.id.toUByte()).common()
    }

    override suspend fun enableLocalUnlock(protector: DeviceProtector, pin: ByteArray?) = backgroundSuspend {
        vault.enableLocalUnlock(protector.native(pin), protector.id.toUByte())
    }

    override suspend fun disableLocalUnlock(protectorId: Int) = background {
        vault.disableLocalUnlock(protectorId.toUByte())
    }

    override fun close() = vault.close()
}

/** Runs a core call off the calling thread, with its errors mapped. */
private suspend fun <T> background(block: () -> T): T =
    withContext(Dispatchers.IO) { mapped(block) }

/** [background] for the core's async calls, which wait on a platform prompt. */
private suspend fun <T> backgroundSuspend(block: suspend () -> T): T =
    withContext(Dispatchers.IO) {
        try {
            block()
        } catch (e: VaultException) {
            throw e.common()
        }
    }

/** Runs [block], then wipes [secret] whether or not it succeeded. */
private inline fun <T> consuming(secret: ByteArray, block: () -> T): T =
    try {
        block()
    } finally {
        secret.wipe()
    }

private inline fun <T> mapped(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw e.common()
    }

private fun VaultException.common(): StrataException {
    return when (this) {
        is VaultException.Rejected -> StrataException(Reason.REJECTED, "rejected $what: $why")
        is VaultException.Alarm ->
            StrataException(Reason.ALARM, "security alarm: ${kind.common()}", kind.common())
        is VaultException.UpdateRequired ->
            StrataException(Reason.UPDATE_REQUIRED, "this vault needs a newer version of Strata (format $found)")
        is VaultException.Locked -> StrataException(Reason.LOCKED, "the vault is locked")
        is VaultException.KeyRotated ->
            StrataException(Reason.KEY_ROTATED, "the vault's key was changed on another device; unlock again")
        is VaultException.ConflictingRotation ->
            StrataException(Reason.CONFLICTING_ROTATION, "another device changed the vault key at the same time")
        is VaultException.WrongCredential ->
            StrataException(Reason.WRONG_CREDENTIAL, "that password or recovery key doesn't unlock this vault")
        is VaultException.RecoveryWords -> StrataException(Reason.RECOVERY_WORDS, detail)
        is VaultException.Policy -> StrataException(Reason.POLICY, detail)
        is VaultException.Rng -> StrataException(Reason.RNG, "the system random number generator is unavailable")
        is VaultException.Io -> StrataException(Reason.IO, "storage error: $detail")
        is VaultException.NotFound -> StrataException(Reason.NOT_FOUND, "no such $what")
        is VaultException.FieldConflict -> StrataException(Reason.FIELD_CONFLICT, "the field has conflicting values")
        is VaultException.Cancelled -> StrataException(Reason.CANCELLED, "cancelled")
        is VaultException.KeyInvalidated -> StrataException(
            Reason.KEY_INVALIDATED,
            "Device unlock stopped working (for example, fingerprints changed). Unlock with the password.",
        )
        is VaultException.ProtectorUnavailable -> StrataException(Reason.PROTECTOR_UNAVAILABLE, "device unlock unavailable: $detail")
        is VaultException.Kdbx -> StrataException(Reason.KEEPASS, detail)
    }
}

private fun AlarmKind.common() = when (this) {
    AlarmKind.ROLLBACK -> Alarm.ROLLBACK
    AlarmKind.FORK -> Alarm.FORK
    AlarmKind.SLOT_SUBSTITUTION -> Alarm.SLOT_SUBSTITUTION
    AlarmKind.FORGERY -> Alarm.FORGERY
}

private fun FfiSyncSummary.common() = SyncSummary(
    applied = applied.toInt(),
    uploaded = uploaded.toInt(),
    held = held.toInt(),
    rejected = rejected.toInt(),
    farFuture = farFuture.toInt(),
    keyRotated = keyRotated,
    lostRotation = lostRotation,
    identityReset = identityReset,
    integrityUnverified = integrityUnverified,
    snapshotWritten = snapshotWritten,
    filesDeleted = filesDeleted.toInt(),
    alarm = alarm?.common(),
)

private fun FfiRotationSummary.common() = RotationSummary(epoch.toInt(), recoveryLost)

private fun EntryEdit.ffi(): FfiEntryEdit = when (this) {
    is EntryEdit.SetField -> FfiEntryEdit.SetField(entryId, name, value, secret)
    is EntryEdit.DeleteEntry -> FfiEntryEdit.DeleteEntry(entryId)
    is EntryEdit.KeepEntry -> FfiEntryEdit.KeepEntry(entryId)
    is EntryEdit.AddTag -> FfiEntryEdit.AddTag(entryId, tag)
    is EntryEdit.RemoveTag -> FfiEntryEdit.RemoveTag(entryId, tag)
}
