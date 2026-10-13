package dev.lockermanwxlf.strata.desktop

import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import dev.lockermanwxlf.strata.App
import dev.lockermanwxlf.strata.ui.VaultController

fun main() = application {
    val scope = rememberCoroutineScope()
    val host = remember { DesktopHost() }
    val controller = remember { VaultController(host, scope).also { it.start() } }
    DisposableEffect(Unit) {
        // Don't leave a secret on the clipboard after the app has gone.
        onDispose { host.clipboard.clearIfStillOurs() }
    }
    Window(
        onCloseRequest = ::exitApplication,
        title = "Strata",
        state = rememberWindowState(width = 900.dp, height = 700.dp),
    ) {
        App(controller)
    }
}
