package dev.lockermanwxlf.strata

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.deleteRecursively
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.pathString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** The common vault API against the real native library, on real folders. */
@OptIn(kotlin.io.path.ExperimentalPathApi::class)
class VaultTest {
    private val root: Path = Files.createTempDirectory("strata-test")
    private val vaultDir = root.resolve("vault").also { Files.createDirectories(it) }.pathString
    private val handles = mutableListOf<VaultHandle>()

    @AfterTest
    fun cleanUp() {
        handles.forEach { it.close() }
        root.deleteRecursively()
    }

    private fun password() = "correct horse battery staple".encodeToByteArray()

    private fun state(device: String) = root.resolve("state-$device").pathString

    private suspend fun create(): CreatedVault =
        StrataCore.createVault(vaultDir, state("laptop"), password(), "Laptop").also { handles += it.vault }

    private suspend fun open(device: String): VaultHandle =
        StrataCore.openVault(vaultDir, state(device), device).also {
            handles += it
            it.unlockPassword(password())
        }

    private fun set(id: String, name: String, value: String) =
        EntryEdit.SetField(id, name, value.encodeToByteArray())

    private fun ByteArray.isWiped() = all { it == 0.toByte() }

    @Test
    fun createEditRevealAndWipe() = runBlocking {
        val typed = password()
        val created = StrataCore.createVault(vaultDir, state("laptop"), typed, "Laptop")
        handles += created.vault
        assertTrue(typed.isWiped(), "the password array is wiped once passed in")
        assertEquals(24, created.recoveryWords.decodeToString().split(' ').size)
        created.recoveryWords.wipe()

        val vault = created.vault
        val id = StrataCore.newEntryId()
        val secret = "hunter2".encodeToByteArray()
        vault.apply(
            listOf(
                set(id, "title", "Bank"),
                set(id, "username", "me"),
                EntryEdit.SetField(id, "password", secret),
                EntryEdit.AddTag(id, "money"),
            ),
        )
        assertTrue(secret.isWiped(), "field values are wiped once applied")

        val summary = vault.entries().single()
        assertEquals("Bank", summary.title)
        assertEquals("me", summary.username)
        assertEquals(listOf("money"), summary.tags)

        // Secret fields carry no value in the detail; reveal hands out a ByteArray.
        val field = vault.entry(id).fields.single { it.name == "password" }
        assertTrue(field.secret)
        assertNull(field.value)
        val revealed = vault.reveal(id, "password")
        assertContentEquals("hunter2".encodeToByteArray(), revealed)
        revealed.wipe()
        assertTrue(revealed.isWiped())
    }

    @Test
    fun lockedAndWrongPassword() = runBlocking {
        val vault = create().vault
        vault.lock()
        assertTrue(vault.isLocked && vault.status().locked)
        val locked = assertFailsWith<StrataException> { vault.entries() }
        assertEquals(StrataException.Reason.LOCKED, locked.reason)
        val wrong = assertFailsWith<StrataException> { vault.unlockPassword("nope".encodeToByteArray()) }
        assertEquals(StrataException.Reason.WRONG_CREDENTIAL, wrong.reason)
        vault.unlockPassword(password())
        assertFalse(vault.isLocked)
    }

    @Test
    fun twoDevicesSyncAndConflict() = runBlocking {
        val laptop = create().vault
        val phone = open("phone")
        val id = StrataCore.newEntryId()
        laptop.apply(listOf(set(id, "title", "Mail")))
        assertEquals(1, phone.sync().applied)
        assertEquals("Mail", phone.entries().single().title)

        laptop.apply(listOf(set(id, "password", "from laptop")))
        phone.apply(listOf(set(id, "password", "from phone")))
        laptop.sync()
        assertEquals(1, laptop.status().conflicts)
        val conflict = assertFailsWith<StrataException> { laptop.reveal(id, "password") }
        assertEquals(StrataException.Reason.FIELD_CONFLICT, conflict.reason)
        val values = laptop.revealConflict(id, "password").map { it.value!!.decodeToString() }.sorted()
        assertEquals(listOf("from laptop", "from phone"), values)
        assertEquals(2, laptop.devices().size)
    }

    @Test
    fun passwordChangeReachesTheOtherDevice() = runBlocking {
        val laptop = create().vault
        val phone = open("phone")
        assertEquals(1, laptop.changePassword("new password".encodeToByteArray()).epoch)
        assertTrue(phone.sync().keyRotated)
        val rotated = assertFailsWith<StrataException> {
            phone.apply(listOf(set(StrataCore.newEntryId(), "title", "x")))
        }
        assertEquals(StrataException.Reason.KEY_ROTATED, rotated.reason)
        phone.lock()
        phone.unlockPassword("new password".encodeToByteArray())
        phone.apply(listOf(set(StrataCore.newEntryId(), "title", "x")))
    }

    @Test
    fun anAlarmIsStateNotAnException() = runBlocking {
        val laptop = create().vault
        laptop.apply(listOf(set(StrataCore.newEntryId(), "title", "x")))
        Files.delete(Path.of(vaultDir, "events").listDirectoryEntries().max())
        assertEquals(Alarm.ROLLBACK, laptop.sync().alarm)
        assertEquals(Alarm.ROLLBACK, laptop.status().alarm)
        assertEquals(1, laptop.entries().size, "still readable")
    }

    @Test
    fun passwordStrengthWarnsOnWeakPasswords() = runBlocking {
        val weak = "password".encodeToByteArray()
        assertTrue(StrataCore.passwordStrength(weak).warn)
        assertTrue(weak.isWiped())
    }

    @Test
    fun recoveryAndKeyManagement() = runBlocking {
        val created = create()
        val laptop = created.vault
        val words = created.recoveryWords

        // A second device joins with the recovery words and names itself.
        val phone = StrataCore.openVault(vaultDir, state("phone"), "Phone").also { handles += it }
        phone.unlockRecovery(words.copyOf())
        phone.renameDevice("Work phone")
        laptop.sync()
        val phoneId = laptop.devices().single { it.name == "Work phone" }.clientId

        // New recovery words replace the old ones.
        val newWords = laptop.replaceRecoveryKey(password())
        val tablet = StrataCore.openVault(vaultDir, state("tablet"), "Tablet").also { handles += it }
        val old = assertFailsWith<StrataException> { tablet.unlockRecovery(words) }
        assertEquals(StrataException.Reason.WRONG_CREDENTIAL, old.reason)
        tablet.unlockRecovery(newWords)
        assertTrue(newWords.isWiped())

        // Revoking the phone retires it and rotates again.
        assertEquals(2, laptop.revokeDevice(phoneId, password()).epoch)
        assertTrue(laptop.devices().single { it.clientId == phoneId }.retired)
        assertEquals(0, laptop.revertFlagged())

        // Nothing to rejoin: this device holds the winning key.
        val rejoin = assertFailsWith<StrataException> { laptop.rejoinPassword(password()) }
        assertEquals(StrataException.Reason.REJECTED, rejoin.reason)

        // Purge removes the entry and the files that held it.
        val id = StrataCore.newEntryId()
        laptop.apply(listOf(set(id, "title", "gone")))
        val purged = laptop.purge(id, password())
        assertEquals(3, purged.rotation.epoch)
        assertEquals(0, purged.eventsLeft)
        assertTrue(laptop.entries().none { it.id == id })
    }
}
