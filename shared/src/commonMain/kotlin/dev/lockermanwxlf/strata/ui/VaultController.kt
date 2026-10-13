package dev.lockermanwxlf.strata.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import dev.lockermanwxlf.strata.AppHost
import dev.lockermanwxlf.strata.DeviceProtector
import dev.lockermanwxlf.strata.EntryEdit
import dev.lockermanwxlf.strata.EntrySummary
import dev.lockermanwxlf.strata.StrataCore
import dev.lockermanwxlf.strata.StrataException
import dev.lockermanwxlf.strata.SyncSummary
import dev.lockermanwxlf.strata.VaultHandle
import dev.lockermanwxlf.strata.VaultStatus
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Where the app is. The controller keeps a stack of these; the last one is shown. */
sealed interface Screen {
    data object Welcome : Screen
    data class Create(val folder: String) : Screen

    /**
     * The recovery words, shown once and then checked. [words] is wiped when the
     * screen is left ([VaultController.finishRecoveryWords]).
     */
    class RecoveryWords(val words: ByteArray) : Screen

    data object Unlock : Screen
    data object Entries : Screen
    data object Trash : Screen
    data class Detail(val id: String) : Screen

    /** Editing an entry; a new one when [isNew]. */
    data class Edit(val id: String, val isNew: Boolean) : Screen
    data class Resolve(val id: String, val field: String) : Screen
    data object Settings : Screen
    data object ChangePassword : Screen
    data object Devices : Screen
    data object Review : Screen
}

/**
 * The app's state and every call into the vault. Screens read the state and call
 * the methods; nothing else touches the vault. Methods that do work launch it on
 * [scope] and return the [Job], so tests can wait for it.
 */
class VaultController(
    private val host: AppHost,
    private val scope: CoroutineScope,
    /** Lock after this long without input. */
    val idleTimeout: Duration = 5.minutes,
    /** Lock this long after the app goes to the background (Android). */
    val backgroundTimeout: Duration = 30.seconds,
    /** Clear a copied secret from the clipboard after this long. */
    val clipboardTimeout: Duration = 30.seconds,
) {
    var stack by mutableStateOf<List<Screen>>(listOf(Screen.Welcome))
        private set
    val screen: Screen get() = stack.last()

    var busy by mutableStateOf(false)
        private set

    /** A message for the user (an error or a confirmation), shown until dismissed. */
    var message by mutableStateOf<String?>(null)
    var folder by mutableStateOf<String?>(null)
        private set
    var entries by mutableStateOf<List<EntrySummary>>(emptyList())
        private set
    var status by mutableStateOf<VaultStatus?>(null)
        private set
    var lastSync by mutableStateOf<SyncSummary?>(null)
        private set
    var query by mutableStateOf("")

    /** This device's biometric or Windows Hello unlock, if the platform has one. */
    val deviceProtector: DeviceProtector? get() = host.deviceProtector

    /** [deviceProtector] can unlock this vault on this device. */
    var deviceUnlockEnabled by mutableStateOf(false)
        private set

    /** The user has seen the alarm screen and chose to keep reading. */
    var alarmAcknowledged by mutableStateOf(false)
        private set

    private var vault: VaultHandle? = null
    private var lastInput = TimeSource.Monotonic.markNow()
    private var clipboardJob: Job? = null
    private var backgroundJob: Job? = null

    val unlocked: Boolean get() = status?.locked == false

    /** Entries matching [query] in the title, username or tags, outside the trash. */
    val visibleEntries: List<EntrySummary>
        get() = entries.filter { !it.deleted && matches(it) }.sortedBy { it.title?.lowercase() ?: "" }
    val trash: List<EntrySummary> get() = entries.filter { it.deleted }

    private fun matches(e: EntrySummary): Boolean {
        val q = query.trim()
        if (q.isEmpty()) return true
        return listOfNotNull(e.title, e.username).any { it.contains(q, ignoreCase = true) } ||
            e.tags.any { it.contains(q, ignoreCase = true) }
    }

    // ---- Navigation -----------------------------------------------------------------

    fun open(screen: Screen) {
        stack = stack + screen
    }

    /** Back one screen. Returns false at the root, so the platform can close the app. */
    fun back(): Boolean {
        if (stack.size <= 1) return false
        stack = stack.dropLast(1)
        return true
    }

    private fun reset(root: Screen) {
        stack = listOf(root)
    }

    // ---- Opening and locking ---------------------------------------------------------

    /** Picks up the vault used last time, if it's still there. */
    fun start() {
        val last = host.lastVaultFolder
        if (last != null && host.isVault(last)) openHandle(last) else reset(Screen.Welcome)
    }

    fun chooseNewVault() = perform {
        val chosen = host.chooseVaultFolder(forNewVault = true) ?: return@perform
        if (host.isVault(chosen)) {
            message = "That folder already holds a vault. Open it instead."
            return@perform
        }
        open(Screen.Create(chosen))
    }

    fun chooseExistingVault() = perform {
        val chosen = host.chooseVaultFolder(forNewVault = false) ?: return@perform
        if (!host.isVault(chosen)) {
            message = "There's no Strata vault in that folder."
            return@perform
        }
        openHandle(chosen)
    }

    private fun openHandle(chosen: String) {
        vault?.close()
        vault = StrataCore.openVault(chosen, host.stateDir, host.defaultDeviceName)
        folder = chosen
        host.lastVaultFolder = chosen
        reset(Screen.Unlock)
        scope.launch { refreshDeviceUnlock() }
    }

    private suspend fun refreshDeviceUnlock() {
        val p = deviceProtector
        deviceUnlockEnabled = p != null && attempt { vault?.localUnlocks() }.orEmpty().contains(p.id)
    }

    /**
     * Unlocks with [deviceProtector], passing [pin] (wiped) when it needs one. A
     * dismissed prompt just returns to the unlock screen.
     */
    fun unlockWithDevice(pin: ByteArray? = null) = perform {
        val v = vault ?: return@perform
        val p = deviceProtector ?: return@perform
        try {
            afterSync(v.unlockLocal(p, pin))
        } catch (e: StrataException) {
            if (e.reason == StrataException.Reason.KEY_INVALIDATED) deviceUnlockEnabled = false
            throw e
        }
        alarmAcknowledged = false
        lastInput = TimeSource.Monotonic.markNow()
        reset(Screen.Entries)
    }

    /** Turns device unlock on (one prompt, or [pin]) or off for this vault on this device. */
    fun setDeviceUnlock(enabled: Boolean, pin: ByteArray? = null) = perform {
        val v = vault ?: return@perform
        val p = deviceProtector ?: return@perform
        if (enabled) v.enableLocalUnlock(p, pin) else v.disableLocalUnlock(p.id)
        refreshDeviceUnlock()
    }

    /** Creates the vault and shows its recovery words. [password] is wiped. */
    fun create(folder: String, password: ByteArray) = perform {
        val created = StrataCore.createVault(folder, host.stateDir, password, host.defaultDeviceName)
        vault?.close()
        vault = created.vault
        this.folder = folder
        host.lastVaultFolder = folder
        alarmAcknowledged = false
        refresh()
        reset(Screen.Entries)
        open(Screen.RecoveryWords(created.recoveryWords))
    }

    /** Leaves the recovery words screen, wiping the words. */
    fun finishRecoveryWords(screen: Screen.RecoveryWords) {
        screen.words.fill(0)
        stack = stack.filterNot { it === screen }
    }

    fun unlock(password: ByteArray) = perform {
        val v = vault ?: return@perform
        afterSync(v.unlockPassword(password))
        alarmAcknowledged = false
        lastInput = TimeSource.Monotonic.markNow()
        reset(Screen.Entries)
    }

    fun unlockWithRecoveryWords(words: ByteArray) = perform {
        val v = vault ?: return@perform
        afterSync(v.unlockRecovery(words))
        alarmAcknowledged = false
        lastInput = TimeSource.Monotonic.markNow()
        reset(Screen.Entries)
    }

    /** Locks now: keys and decrypted values are dropped, and the unlock screen shows. */
    fun lock() = scope.launch {
        // Recovery words still on screen are wiped with it.
        stack.filterIsInstance<Screen.RecoveryWords>().forEach { it.words.fill(0) }
        entries = emptyList()
        status = status?.copy(locked = true)
        if (vault != null) reset(Screen.Unlock) else reset(Screen.Welcome)
        vault?.lock()
        status = vault?.status()
    }

    /** Forgets this vault on this device's welcome screen (the files stay). */
    fun switchVault() = scope.launch {
        vault?.lock()
        vault?.close()
        vault = null
        folder = null
        host.lastVaultFolder = null
        entries = emptyList()
        status = null
        reset(Screen.Welcome)
    }

    // ---- Auto-lock ------------------------------------------------------------------

    /** Call on any user input. */
    fun touch() {
        lastInput = TimeSource.Monotonic.markNow()
    }

    /** Locks if there has been no input for [idleTimeout]. Call periodically. */
    fun checkIdle() {
        if (unlocked && lastInput.elapsedNow() >= idleTimeout) lock()
    }

    fun backgrounded() {
        if (!unlocked) return
        backgroundJob?.cancel()
        backgroundJob = scope.launch {
            delay(backgroundTimeout)
            lock()
        }
    }

    fun foregrounded() {
        backgroundJob?.cancel()
        backgroundJob = null
    }

    // ---- Reading ---------------------------------------------------------------------

    fun sync() = perform {
        val v = vault ?: return@perform
        afterSync(v.sync())
    }

    /** Syncs without the busy indicator or error messages: for the periodic sync. */
    fun syncQuietly() = scope.launch {
        val v = vault ?: return@launch
        if (!unlocked || busy) return@launch
        try {
            afterSync(v.sync())
        } catch (_: StrataException) {
            // The next manual sync shows what's wrong.
        }
    }

    private suspend fun afterSync(summary: SyncSummary) {
        lastSync = summary
        refresh()
    }

    private suspend fun refresh() {
        val v = vault ?: return
        status = v.status()
        entries = if (status?.locked == false) v.entries() else emptyList()
        // An unlock or a key change can drop or re-wrap the local slot.
        refreshDeviceUnlock()
    }

    suspend fun entry(id: String) = vault?.entry(id)

    /** One field's value, for display. The caller wipes it. */
    suspend fun reveal(id: String, field: String): ByteArray? = attempt { vault?.reveal(id, field) }

    suspend fun conflictCandidates(id: String, field: String) =
        attempt { vault?.revealConflict(id, field) }.orEmpty()

    suspend fun devices() = attempt { vault?.devices() }.orEmpty()

    /** Copies a field to the clipboard and clears it after [clipboardTimeout]. */
    fun copy(id: String, field: String) = perform {
        val value = vault?.reveal(id, field) ?: return@perform
        host.clipboard.copy(value)
        clipboardJob?.cancel()
        clipboardJob = scope.launch {
            delay(clipboardTimeout)
            host.clipboard.clearIfStillOurs()
        }
        message = "Copied. The clipboard clears in ${clipboardTimeout.inWholeSeconds} seconds."
    }

    // ---- Changes ---------------------------------------------------------------------

    /** Applies [edits] (their values are wiped) and returns to [then]. */
    fun save(edits: List<EntryEdit>, then: () -> Unit = { back() }) = perform {
        if (edits.isNotEmpty()) vault?.apply(edits)
        refresh()
        then()
    }

    fun delete(id: String) = save(listOf(EntryEdit.DeleteEntry(id))) { back() }

    /** Keeps an entry deleted elsewhere, or restores it from the trash. */
    fun keep(id: String) = save(listOf(EntryEdit.KeepEntry(id))) {}

    /** Settles a conflict with [value] (wiped), or by removing the field (`null`). */
    fun resolve(id: String, field: String, value: ByteArray?) =
        save(listOf(EntryEdit.SetField(id, field, value, secret = true)))

    fun purge(id: String, password: ByteArray) = perform {
        val summary = vault?.purge(id, password) ?: return@perform
        refresh()
        message = if (summary.eventsLeft + summary.snapshotsLeft == 0) {
            "Deleted for good."
        } else {
            "Deleted. Some files written by other devices at the same time may still mention it; " +
                "sync them and delete it again."
        }
    }

    fun changePassword(newPassword: ByteArray) = perform {
        val rotated = vault?.changePassword(newPassword) ?: return@perform
        refresh()
        back()
        message = "Password changed. Other devices ask for the new password next time they sync." +
            if (rotated.recoveryLost) " The recovery key couldn't be kept: make a new one." else ""
    }

    fun replaceRecoveryKey(password: ByteArray) = perform {
        val words = vault?.replaceRecoveryKey(password) ?: return@perform
        refresh()
        open(Screen.RecoveryWords(words))
    }

    fun renameDevice(name: String) = perform {
        vault?.renameDevice(name)
        refresh()
    }

    fun revokeDevice(clientId: String, password: ByteArray) = perform {
        vault?.revokeDevice(clientId, password)
        refresh()
        message = "Device revoked. It can't read anything written from now on."
    }

    fun revertFlagged() = perform {
        val n = vault?.revertFlagged() ?: return@perform
        refresh()
        message = if (n == 0) "Nothing to revert." else "Reverted $n change${if (n == 1) "" else "s"}."
    }

    fun rejoin(password: ByteArray) = perform {
        vault?.rejoinPassword(password)
        refresh()
        message = "This device now uses the other device's key."
    }

    /** See [AppHost.setSecureScreen]. */
    fun secureScreen(secure: Boolean) = host.setSecureScreen(secure)

    fun acknowledgeAlarm() {
        alarmAcknowledged = true
    }

    fun newEntryId(): String = StrataCore.newEntryId()

    // ---- Plumbing --------------------------------------------------------------------

    /** Runs [block] with the busy indicator, turning failures into [message]. */
    private fun perform(block: suspend () -> Unit): Job = scope.launch {
        busy = true
        try {
            block()
        } catch (e: StrataException) {
            if (e.reason != StrataException.Reason.CANCELLED) message = e.message
            if (e.reason == StrataException.Reason.KEY_ROTATED) refresh()
        } finally {
            busy = false
        }
    }

    private suspend fun <T> attempt(block: suspend () -> T): T? = try {
        block()
    } catch (e: StrataException) {
        message = e.message
        null
    }
}
