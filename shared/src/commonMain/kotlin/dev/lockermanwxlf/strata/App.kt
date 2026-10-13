package dev.lockermanwxlf.strata

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Snackbar
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.key
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import dev.lockermanwxlf.strata.ui.AlarmScreen
import dev.lockermanwxlf.strata.ui.ChangePasswordScreen
import dev.lockermanwxlf.strata.ui.CreateScreen
import dev.lockermanwxlf.strata.ui.DetailScreen
import dev.lockermanwxlf.strata.ui.DevicesScreen
import dev.lockermanwxlf.strata.ui.EditScreen
import dev.lockermanwxlf.strata.ui.EntriesScreen
import dev.lockermanwxlf.strata.ui.RecoveryWordsScreen
import dev.lockermanwxlf.strata.ui.ResolveScreen
import dev.lockermanwxlf.strata.ui.ReviewScreen
import dev.lockermanwxlf.strata.ui.Screen
import dev.lockermanwxlf.strata.ui.SettingsScreen
import dev.lockermanwxlf.strata.ui.TrashScreen
import dev.lockermanwxlf.strata.ui.UnlockScreen
import dev.lockermanwxlf.strata.ui.VaultController
import dev.lockermanwxlf.strata.ui.WelcomeScreen
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.delay

/** Sync in the background this often while unlocked. */
private const val SYNC_EVERY_SECONDS = 60

@Composable
fun App(controller: VaultController) {
    val c = controller
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
        Surface(Modifier.fillMaxSize().trackInput(c::touch)) {
            Box(Modifier.fillMaxSize().safeDrawingPadding()) {
                val alarm = c.status?.alarm
                if (alarm != null && c.unlocked && !c.alarmAcknowledged) {
                    AlarmScreen(c, alarm)
                } else {
                    // Keyed by position too, so a screen's state starts fresh each time it's opened.
                    key(c.stack.size, c.screen) { ScreenFor(c) }
                }
                if (c.busy) LinearProgressIndicator(Modifier.fillMaxWidth().align(Alignment.TopCenter))
                c.message?.let { message ->
                    Snackbar(
                        modifier = Modifier.align(Alignment.BottomCenter).padding(16.dp),
                        action = { TextButton(onClick = { c.message = null }) { Text("OK") } },
                    ) { Text(message) }
                    LaunchedEffect(message) {
                        delay(8.seconds)
                        if (c.message == message) c.message = null
                    }
                }
            }
        }
    }
    LaunchedEffect(c.unlocked) {
        var ticks = 0
        while (c.unlocked) {
            delay(1.seconds)
            c.checkIdle()
            if (++ticks % SYNC_EVERY_SECONDS == 0) c.syncQuietly()
        }
    }
}

@Composable
private fun ScreenFor(c: VaultController) {
    when (val s = c.screen) {
        Screen.Starting -> {}
        Screen.Welcome -> WelcomeScreen(c)
        is Screen.Create -> CreateScreen(c, s.folder)
        is Screen.RecoveryWords -> RecoveryWordsScreen(c, s)
        Screen.Unlock -> UnlockScreen(c)
        Screen.Entries -> EntriesScreen(c)
        Screen.Trash -> TrashScreen(c)
        is Screen.Detail -> DetailScreen(c, s.id)
        is Screen.Edit -> EditScreen(c, s.id, s.isNew)
        is Screen.Resolve -> ResolveScreen(c, s.id, s.field)
        Screen.Settings -> SettingsScreen(c)
        Screen.ChangePassword -> ChangePasswordScreen(c)
        Screen.Devices -> DevicesScreen(c)
        Screen.Review -> ReviewScreen(c)
    }
}

/** Calls [onInput] for every pointer and key event, without consuming them (for auto-lock). */
private fun Modifier.trackInput(onInput: () -> Unit): Modifier =
    pointerInput(Unit) {
        awaitPointerEventScope {
            while (true) {
                awaitPointerEvent(PointerEventPass.Initial)
                onInput()
            }
        }
    }.onPreviewKeyEvent {
        onInput()
        false
    }
