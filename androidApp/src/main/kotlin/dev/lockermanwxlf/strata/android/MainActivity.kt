package dev.lockermanwxlf.strata.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dev.lockermanwxlf.strata.App
import dev.lockermanwxlf.strata.ui.VaultController
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel

class MainActivity : ComponentActivity() {
    private val scope = MainScope()
    private lateinit var controller: VaultController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keep vault contents out of screenshots, screen recording and the recents thumbnail.
        // Debug builds allow screenshots for UI work; release builds always block them.
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        enableEdgeToEdge()
        // Rotation and similar changes don't recreate the activity (see the manifest), so
        // the controller, and with it the unlocked vault, lives as long as the activity.
        controller = VaultController(AndroidHost(this), scope)
        controller.start()
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    if (!controller.back()) finish()
                }
            },
        )
        setContent { App(controller) }
    }

    override fun onStart() {
        super.onStart()
        controller.foregrounded()
    }

    override fun onStop() {
        super.onStop()
        controller.backgrounded()
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}
