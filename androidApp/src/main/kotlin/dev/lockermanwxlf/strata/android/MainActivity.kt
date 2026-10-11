package dev.lockermanwxlf.strata.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dev.lockermanwxlf.strata.App

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keep vault contents out of screenshots, screen recording and the recents thumbnail.
        // Debug builds allow screenshots for UI work; release builds always block them.
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        enableEdgeToEdge()
        setContent { App() }
    }
}
