package dev.lockermanwxlf.strata

import dev.lockermanwxlf.strata.ui.Screen
import dev.lockermanwxlf.strata.ui.VaultController
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.deleteRecursively
import kotlin.io.path.pathString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

/** A host whose folder picker, clipboard and screen flag are under the test's control. */
internal class FakeHost(root: Path) : AppHost {
    override val stateDir = root.resolve("state").pathString
    override val defaultDeviceName = "Test machine"
    override var lastVaultFolder: String? = null
    var nextFolder: String? = null
    var secure = false
    val copied = mutableListOf<String>()
    var clears = 0

    override suspend fun chooseVaultFolder(forNewVault: Boolean) = nextFolder

    override suspend fun isVault(folder: String) = File(folder, "strata-vault").isFile

    var nextFile: PickedFile? = null
    val saved = mutableListOf<Pair<String, ByteArray>>()

    override suspend fun openFile() = nextFile

    override suspend fun saveFile(name: String, bytes: ByteArray): Boolean {
        saved += name to bytes
        return true
    }

    override val deviceProtector: DeviceProtector? = null

    override val clipboard = object : SecretClipboard {
        override fun copy(value: ByteArray) {
            copied += value.decodeToString()
            value.fill(0)
        }

        override fun clearIfStillOurs() {
            clears++
        }
    }

    override fun setSecureScreen(secure: Boolean) {
        this.secure = secure
    }
}

/** The controller's flows against the real library, without any UI. */
@OptIn(kotlin.io.path.ExperimentalPathApi::class)
class ControllerTest {
    private val root: Path = Files.createTempDirectory("strata-ui-test")
    private val vaultDir = root.resolve("vault").also { Files.createDirectories(it) }.pathString
    private val host = FakeHost(root).apply { nextFolder = vaultDir }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @AfterTest
    fun cleanUp() {
        scope.cancel()
        root.deleteRecursively()
    }

    private fun controller(
        idle: Duration = 5.minutes,
        background: Duration = 5.minutes,
        clipboard: Duration = 5.minutes,
    ) = VaultController(host, scope, idle, background, clipboard)

    private fun pw(text: String = "correct horse battery staple") = text.encodeToByteArray()

    /** Creates a vault through the controller and dismisses the recovery words. */
    private suspend fun created(c: VaultController = controller()): VaultController {
        c.chooseNewVault().join()
        assertEquals(Screen.Create(vaultDir), c.screen)
        c.create(vaultDir, pw()).join()
        val words = assertIs<Screen.RecoveryWords>(c.screen)
        assertEquals(24, words.words.decodeToString().split(' ').size)
        c.finishRecoveryWords(words)
        assertTrue(words.words.all { it == 0.toByte() }, "the words are wiped")
        assertEquals(Screen.Entries, c.screen)
        return c
    }

    private suspend fun eventually(what: String, check: () -> Boolean) {
        repeat(200) {
            if (check()) return
            delay(10)
        }
        throw AssertionError("timed out waiting for $what")
    }

    @Test
    fun createThenStartAgainAtTheUnlockScreen() = runBlocking<Unit> {
        created()
        assertEquals(vaultDir, host.lastVaultFolder)

        val next = controller()
        next.start().join()
        assertEquals(Screen.Unlock, next.screen)
        next.unlock(pw("wrong")).join()
        assertEquals(Screen.Unlock, next.screen)
        assertNotNull(next.message)
        next.unlock(pw()).join()
        assertEquals(Screen.Entries, next.screen)
        assertTrue(next.unlocked)
    }

    @Test
    fun editSearchCopyAndTrash() = runBlocking<Unit> {
        val c = created(controller(clipboard = 50.milliseconds))
        val bank = c.newEntryId()
        val mail = c.newEntryId()
        c.save(
            listOf(
                EntryEdit.SetField(bank, "title", "Bank".encodeToByteArray()),
                EntryEdit.SetField(bank, "password", "hunter2".encodeToByteArray()),
                EntryEdit.AddTag(bank, "money"),
                EntryEdit.SetField(mail, "title", "Mail".encodeToByteArray()),
            ),
        ) {}.join()
        assertEquals(listOf("Bank", "Mail"), c.visibleEntries.map { it.title })
        c.query = "MON"
        assertEquals(listOf("Bank"), c.visibleEntries.map { it.title }, "tags match too, ignoring case")
        c.query = ""

        c.copy(bank, "password").join()
        assertEquals(listOf("hunter2"), host.copied)
        eventually("the clipboard to clear") { host.clears == 1 }

        c.open(Screen.Detail(mail))
        c.delete(mail).join()
        assertEquals(Screen.Entries, c.screen)
        assertEquals(listOf("Mail"), c.trash.map { it.title })
        c.keep(mail).join()
        assertTrue(c.trash.isEmpty())
    }

    @Test
    fun idleAndBackgroundLock() = runBlocking<Unit> {
        val c = created(controller(idle = 50.milliseconds, background = 50.milliseconds))
        c.touch()
        c.checkIdle()
        assertTrue(c.unlocked, "not idle yet")
        delay(100)
        c.checkIdle()
        eventually("the idle lock") { !c.unlocked && c.screen == Screen.Unlock }

        c.unlock(pw()).join()
        c.backgrounded()
        c.foregrounded()
        delay(100)
        assertTrue(c.unlocked, "coming back in time cancels the lock")
        c.backgrounded()
        eventually("the background lock") { !c.unlocked }
        assertTrue(c.entries.isEmpty(), "decrypted entries go with the lock")
    }

    @Test
    fun lockingWipesRecoveryWordsStillOnScreen() = runBlocking<Unit> {
        val c = controller()
        c.chooseNewVault().join()
        c.create(vaultDir, pw()).join()
        val words = assertIs<Screen.RecoveryWords>(c.screen)
        c.lock().join()
        assertTrue(words.words.all { it == 0.toByte() })
        assertEquals(Screen.Unlock, c.screen)
    }

    @Test
    fun changePasswordThenUnlockWithIt() = runBlocking<Unit> {
        val c = created()
        c.open(Screen.Settings)
        c.open(Screen.ChangePassword)
        c.changePassword(pw("a new password")).join()
        assertEquals(Screen.Settings, c.screen)
        c.lock().join()
        c.unlock(pw()).join()
        assertTrue(!c.unlocked)
        c.unlock(pw("a new password")).join()
        assertTrue(c.unlocked)
    }

    /** The folder's files, by path, as a backup or a sync tool's version history would keep them. */
    private fun folderFiles(): Map<String, ByteArray> {
        val root = File(vaultDir)
        return root.walkTopDown().filter { it.isFile }.associate { it.relativeTo(root).path to it.readBytes() }
    }

    private fun replaceFolder(files: Map<String, ByteArray>) {
        File(vaultDir).listFiles()!!.forEach { it.deleteRecursively() }
        files.forEach { (path, bytes) -> File(vaultDir, path).apply { parentFile.mkdirs() }.writeBytes(bytes) }
    }

    @Test
    fun aRolledBackFolderIsRepairedFromThisDevicesCopy() = runBlocking<Unit> {
        val c = created()
        c.save(listOf(EntryEdit.SetField(c.newEntryId(), "title", "Old".encodeToByteArray()))) {}.join()
        c.sync().join()
        val backup = folderFiles()
        c.save(listOf(EntryEdit.SetField(c.newEntryId(), "title", "New".encodeToByteArray()))) {}.join()
        c.sync().join()

        // The sync tool goes back to the older folder: an alarm, and files to put back.
        replaceFolder(backup)
        c.sync().join()
        assertNotNull(c.status?.alarm)
        assertTrue(c.restorable > 0)
        c.restoreFromCopy().join()
        assertEquals(null, c.status?.alarm)
        assertEquals(0, c.restorable)
        assertEquals(listOf("New", "Old"), c.visibleEntries.map { it.title })

        // Wiped while locked: the unlock screen offers the files back, then unlock works.
        c.lock().join()
        replaceFolder(emptyMap())
        c.unlock(pw()).join()
        assertEquals(Screen.Unlock, c.screen)
        assertTrue(c.restorable > 0)
        c.restoreFromCopy().join()
        c.unlock(pw()).join()
        assertEquals(Screen.Entries, c.screen)
        assertEquals(listOf("New", "Old"), c.visibleEntries.map { it.title })

        // Or go back on purpose: start over on the older folder.
        replaceFolder(backup)
        c.sync().join()
        assertNotNull(c.status?.alarm)
        c.startOver().join()
        assertEquals(Screen.Unlock, c.screen)
        c.unlock(pw()).join()
        assertEquals(null, c.status?.alarm)
        assertEquals(listOf("Old"), c.visibleEntries.map { it.title })
    }

    @Test
    fun keepassImportAndExport() = runBlocking<Unit> {
        val c = created()
        val fixture = File("../core/strata-core/tests/fixtures/kdbx/keepassxc.kdbx").readBytes()
        c.open(Screen.ImportKeePass)
        val keyfileBytes = byteArrayOf(1, 2, 3)
        c.importKdbx(PickedFile("keepassxc.kdbx", fixture), pw("fixture-password"), PickedFile("k", keyfileBytes)).join()
        // The fixture has no key file, so the extra one makes the key wrong, and is wiped.
        assertTrue(keyfileBytes.all { it == 0.toByte() })
        assertEquals(Screen.ImportKeePass, c.screen)
        assertNotNull(c.message)

        c.importKdbx(PickedFile("keepassxc.kdbx", fixture), pw("fixture-password"), null).join()
        assertEquals(listOf("Bank", "Mail", "Visa"), c.visibleEntries.map { it.title })
        assertEquals(Screen.Entries, c.screen)
        val message = assertNotNull(c.message)
        assertTrue(message.startsWith("Imported 3 entries."), message)
        assertTrue("2 older versions" in message, message)

        c.exportKdbx(pw("export password")).join()
        val (name, bytes) = host.saved.single()
        assertEquals("Strata export.kdbx", name)
        // The KDBX signature.
        assertEquals(listOf(0x03, 0xD9, 0xA2, 0x9A), bytes.take(4).map { it.toInt() and 0xff })
        assertTrue(assertNotNull(c.message).startsWith("Exported 3 entries."))
    }

    @Test
    fun openingAFolderWithoutAVaultSaysSo() = runBlocking<Unit> {
        val c = controller()
        c.start().join()
        assertEquals(Screen.Welcome, c.screen)
        host.nextFolder = root.resolve("empty").also { Files.createDirectories(it) }.pathString
        c.chooseExistingVault().join()
        assertEquals(Screen.Welcome, c.screen)
        assertNotNull(c.message)
    }
}
