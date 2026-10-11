package dev.lockermanwxlf.strata.desktop

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import dev.lockermanwxlf.strata.App

fun main() = application {
    Window(onCloseRequest = ::exitApplication, title = "Strata") {
        App()
    }
}
