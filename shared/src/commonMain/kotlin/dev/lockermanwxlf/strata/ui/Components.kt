package dev.lockermanwxlf.strata.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** The frame every screen uses: a title bar with back and actions, then scrolling content. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScreenFrame(
    title: String,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
    scroll: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    if (onBack != null) TextButton(onClick = onBack) { Text("Back") }
                },
                actions = { Row { actions() } },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            val inner = Modifier.widthIn(max = 720.dp).fillMaxWidth().padding(horizontal = 16.dp)
            Column(
                if (scroll) inner.verticalScroll(rememberScrollState()) else inner,
                verticalArrangement = Arrangement.spacedBy(12.dp),
                content = {
                    Spacer(Modifier)
                    content()
                },
            )
        }
    }
}

/**
 * A password field. Its state stays inside Compose; read it with [takeUtf8], which
 * clears it. Cleared too when it leaves the screen.
 */
@Composable
fun PasswordField(state: TextFieldState, label: String, modifier: Modifier = Modifier.fillMaxWidth()) {
    OutlinedSecureTextField(state = state, label = { Text(label) }, modifier = modifier)
    DisposableEffect(state) { onDispose { state.clearText() } }
}

/** A highlighted note: warnings, conflicts, "deleted elsewhere" and the like. */
@Composable
fun Banner(text: String, warning: Boolean = false, actions: @Composable () -> Unit = {}) {
    val colors = if (warning) {
        CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        )
    } else {
        CardDefaults.cardColors()
    }
    Card(colors = colors, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { actions() }
        }
    }
}

/** Asks for the vault password before something that rotates the key. */
@Composable
fun PasswordDialog(
    title: String,
    explanation: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: (ByteArray) -> Unit,
) {
    val password = rememberTextFieldState()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(explanation)
                PasswordField(password, "Password")
            }
        },
        confirmButton = {
            TextButton(enabled = !password.isEmpty, onClick = { onConfirm(password.takeUtf8()) }) {
                Text(confirmLabel)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** A yes/no question. */
@Composable
fun ConfirmDialog(title: String, text: String, confirmLabel: String, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirmLabel) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium)
}

/** Keeps the window out of screenshots while the calling screen is shown (Android). */
@Composable
fun VaultController.SecureWhileShown() {
    DisposableEffect(this) {
        secureScreen(true)
        onDispose { secureScreen(false) }
    }
}
