package dev.lockermanwxlf.strata

import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import androidx.compose.ui.use
import dev.lockermanwxlf.strata.ui.Screen
import dev.lockermanwxlf.strata.ui.VaultController
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.deleteRecursively
import kotlin.io.path.pathString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.jetbrains.skia.EncodedImageFormat

/**
 * Composes every screen against a real vault and renders it to a PNG in
 * `build/screenshots`. A screen that throws while composing fails the test; the
 * images are for looking at.
 */
@OptIn(kotlin.io.path.ExperimentalPathApi::class)
class ScreenshotTest {
    private val root: Path = Files.createTempDirectory("strata-shots")
    private val vaultDir = root.resolve("vault").also { Files.createDirectories(it) }.pathString
    private val host = FakeHost(root).apply { nextFolder = vaultDir }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val out = File("build/screenshots").apply { mkdirs() }

    @AfterTest
    fun cleanUp() {
        scope.cancel()
        root.deleteRecursively()
    }

    private fun shoot(name: String, c: VaultController, width: Int = 420, height: Int = 860) {
        ImageComposeScene(width, height, Density(1f)) { App(c) }.use { scene ->
            // A few frames, so effects (loading an entry, say) have run.
            repeat(4) { frame ->
                scene.render(frame * 50_000_000L)
                Thread.sleep(100)
            }
            val png = scene.render(400_000_000L).encodeToData(EncodedImageFormat.PNG)!!.bytes
            File(out, "$name.png").writeBytes(png)
        }
    }

    @Test
    fun everyScreenComposes() = runBlocking<Unit> {
        val c = VaultController(host, scope)
        shoot("01-welcome", c)
        c.chooseNewVault().join()
        shoot("02-create", c)
        c.create(vaultDir, "correct horse battery staple".encodeToByteArray()).join()
        shoot("03-recovery-words", c)
        c.finishRecoveryWords(c.screen as Screen.RecoveryWords)

        val bank = c.newEntryId()
        c.save(
            listOf(
                EntryEdit.SetField(bank, "title", "Bank".encodeToByteArray()),
                EntryEdit.SetField(bank, "username", "alice@example.com".encodeToByteArray()),
                EntryEdit.SetField(bank, "password", "hunter2".encodeToByteArray()),
                EntryEdit.SetField(bank, "url", "https://bank.example".encodeToByteArray()),
                EntryEdit.AddTag(bank, "money"),
            ),
        ) {}.join()
        for (title in listOf("Mail", "Work VPN", "Router")) {
            val id = c.newEntryId()
            c.save(listOf(EntryEdit.SetField(id, "title", title.encodeToByteArray()))) {}.join()
        }
        shoot("04-entries", c)
        c.open(Screen.Detail(bank))
        shoot("05-detail", c)
        c.open(Screen.Edit(bank, isNew = false))
        shoot("06-edit", c)
        c.back()
        c.back()
        c.open(Screen.Settings)
        shoot("07-settings", c)
        c.open(Screen.Devices)
        shoot("08-devices", c)
        c.back()
        c.open(Screen.ChangePassword)
        shoot("09-change-password", c)
        c.lock().join()
        shoot("10-unlock", c)
        c.unlock("correct horse battery staple".encodeToByteArray()).join()
        shoot("11-entries-wide", c, width = 1000, height = 700)
    }
}
