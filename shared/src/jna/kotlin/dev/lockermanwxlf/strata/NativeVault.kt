package dev.lockermanwxlf.strata

// The bindings use JNA, so this file compiles separately for each JVM-based target
// (desktop and Android) from this one source directory, like the bindings themselves.
// It maps the generated API onto the common one in Vault.kt.

import dev.lockermanwxlf.strata.StrataException.Reason
import dev.lockermanwxlf.strata.core.ffi.AlarmKind
import dev.lockermanwxlf.strata.core.ffi.Vault
import dev.lockermanwxlf.strata.core.ffi.VaultException
import dev.lockermanwxlf.strata.core.ffi.coreVersion
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import dev.lockermanwxlf.strata.core.ffi.EntryEdit as FfiEntryEdit
import dev.lockermanwxlf.strata.core.ffi.RotationSummary as FfiRotationSummary
import dev.lockermanwxlf.strata.core.ffi.SyncSummary as FfiSyncSummary
import dev.lockermanwxlf.strata.core.ffi.createVault as ffiCreateVault
import dev.lockermanwxlf.strata.core.ffi.defaultStateDir as ffiDefaultStateDir
import dev.lockermanwxlf.strata.core.ffi.generatePassword as ffiGeneratePassword
import dev.lockermanwxlf.strata.core.ffi.newEntryId as ffiNewEntryId
import dev.lockermanwxlf.strata.core.ffi.passwordStrength as ffiPasswordStrength

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

internal actual suspend fun nativePasswordStrength(password: ByteArray): StrengthEstimate = background {
    consuming(password) {
        ffiPasswordStrength(password).let { StrengthEstimate(it.guessesLog10, it.warn) }
    }
}

internal actual fun nativeNewEntryId(): String = mapped { ffiNewEntryId() }

internal actual fun nativeGeneratePassword(length: Int, symbols: Boolean): ByteArray =
    mapped { ffiGeneratePassword(length.toUInt(), symbols) }

internal actual fun nativeDefaultStateDir(): String? = ffiDefaultStateDir()

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

    override fun close() = vault.close()
}

/** Runs a core call off the calling thread, with its errors mapped. */
private suspend fun <T> background(block: () -> T): T =
    withContext(Dispatchers.IO) { mapped(block) }

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
