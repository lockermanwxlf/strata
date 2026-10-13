package dev.lockermanwxlf.strata

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun App() {
    // runCatching also catches UnsatisfiedLinkError, so a missing native library
    // shows up on screen instead of crashing the app.
    val core = remember { runCatching { StrataCore.version() } }

    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            Column(
                // The background draws edge-to-edge; content stays clear of system bars and cutouts.
                modifier = Modifier.safeDrawingPadding().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Strata", style = MaterialTheme.typography.headlineMedium)
                core.fold(
                    onSuccess = { Text("Rust core loaded (v$it)") },
                    onFailure = {
                        Text(
                            "Rust core failed to load: ${it.message ?: it::class.simpleName}",
                            color = MaterialTheme.colorScheme.error,
                        )
                    },
                )
            }
        }
    }
}
