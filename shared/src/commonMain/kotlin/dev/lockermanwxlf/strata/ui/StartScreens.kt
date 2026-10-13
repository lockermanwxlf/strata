package dev.lockermanwxlf.strata.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.lockermanwxlf.strata.StrataCore
import kotlinx.coroutines.launch

@Composable
fun WelcomeScreen(c: VaultController) {
    ScreenFrame("Strata") {
        Text("Your passwords, encrypted on this device, synced as plain files through any folder you choose.")
        Button(onClick = { c.chooseNewVault() }, modifier = Modifier.fillMaxWidth()) { Text("Create a new vault") }
        OutlinedButton(onClick = { c.chooseExistingVault() }, modifier = Modifier.fillMaxWidth()) {
            Text("Open an existing vault")
        }
        Hint(
            "To use the vault on several devices, put it in a folder you sync with another tool " +
                "(Syncthing, a cloud drive, a network share). Strata only ever adds files, so syncing can't corrupt it.",
        )
    }
}

@Composable
fun CreateScreen(c: VaultController, folder: String) {
    val password = rememberTextFieldState()
    val confirm = rememberTextFieldState()
    var weak by remember { mutableStateOf(false) }
    var acceptWeak by remember { mutableStateOf(false) }
    var mismatch by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    ScreenFrame("New vault", onBack = { c.back() }) {
        val label by produceState(folder, folder) { value = c.describe(folder) }
        Text("Folder: $label", style = MaterialTheme.typography.bodySmall)
        Text(
            "Choose the password you'll unlock the vault with. It can't be recovered, but the recovery " +
                "words shown next can always open the vault.",
        )
        PasswordField(password, "Password")
        PasswordField(confirm, "Repeat the password")
        if (mismatch) Text("The passwords don't match.", color = MaterialTheme.colorScheme.error)
        if (weak) {
            Banner(
                "This password looks easy to guess. Anyone who gets a copy of the vault files can try " +
                    "passwords as fast as their hardware allows.",
                warning = true,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = acceptWeak, onCheckedChange = { acceptWeak = it })
                    Text("Use it anyway")
                }
            }
        }
        Button(
            enabled = !password.isEmpty && !c.busy,
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                mismatch = !password.sameTextAs(confirm)
                if (mismatch) return@Button
                scope.launch {
                    // A copy for the estimate; the fields stay filled while the user decides.
                    weak = StrataCore.passwordStrength(password.text.utf8()).warn
                    if (weak && !acceptWeak) return@launch
                    confirm.takeUtf8().fill(0)
                    c.create(folder, password.takeUtf8())
                }
            },
        ) { Text("Create vault") }
    }
}

/** Shows the recovery words once, then checks three of them. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun RecoveryWordsScreen(c: VaultController, screen: Screen.RecoveryWords) {
    c.SecureWhileShown()
    // Displaying the words needs strings: the documented exception for on-screen text.
    val words = remember(screen) { screen.words.decodeToString().split(' ') }
    var checking by remember { mutableStateOf(false) }
    val positions = remember(screen) { words.indices.shuffled().take(3).sorted() }

    ScreenFrame("Recovery words") {
        if (!checking) {
            Text(
                "Write these 24 words down, in order, and keep them somewhere safe and offline. " +
                    "They open the vault if you forget your password. They won't be shown again.",
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                words.forEachIndexed { i, w ->
                    Text(
                        "${i + 1}. $w",
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.width(140.dp),
                    )
                }
            }
            Button(onClick = { checking = true }, modifier = Modifier.fillMaxWidth()) { Text("I've written them down") }
        } else {
            Text("Check your copy: type these words.")
            val answers = positions.map { rememberTextFieldState() }
            var wrong by remember { mutableStateOf(false) }
            positions.zip(answers).forEach { (i, state) ->
                OutlinedTextField(state = state, label = { Text("Word ${i + 1}") }, modifier = Modifier.fillMaxWidth())
            }
            if (wrong) Text("That doesn't match. Check your copy.", color = MaterialTheme.colorScheme.error)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { checking = false }) { Text("Show the words again") }
                Button(onClick = {
                    wrong = positions.zip(answers).any { (i, state) ->
                        state.text.toString().trim().lowercase() != words[i]
                    }
                    if (!wrong) c.finishRecoveryWords(screen)
                }) { Text("Done") }
            }
        }
    }
}

@Composable
fun UnlockScreen(c: VaultController) {
    val password = rememberTextFieldState()
    val words = rememberTextFieldState()
    var useWords by remember { mutableStateOf(false) }

    ScreenFrame("Unlock") {
        c.folderLabel?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        if (!useWords) {
            PasswordField(password, "Password")
            Button(
                enabled = !password.isEmpty && !c.busy,
                onClick = { c.unlock(password.takeUtf8()) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Unlock") }
            val device = c.deviceProtector
            if (device != null && c.deviceUnlockEnabled) {
                if (device.needsPin) {
                    val pin = rememberTextFieldState()
                    PasswordField(pin, "Or the PIN")
                    OutlinedButton(
                        enabled = !pin.isEmpty && !c.busy,
                        onClick = { c.unlockWithDevice(pin.takeUtf8()) },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Unlock with the PIN") }
                } else {
                    OutlinedButton(
                        enabled = !c.busy,
                        onClick = { c.unlockWithDevice() },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Unlock with ${device.label}") }
                }
            }
            TextButton(onClick = { useWords = true }) { Text("Use the recovery words instead") }
        } else {
            OutlinedTextField(
                state = words,
                label = { Text("The 24 recovery words") },
                modifier = Modifier.fillMaxWidth(),
            )
            DisposableEffect(words) { onDispose { words.clearText() } }
            Button(
                enabled = !words.isEmpty && !c.busy,
                onClick = { c.unlockWithRecoveryWords(words.takeUtf8()) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Unlock") }
            Hint("After unlocking with the recovery words, change the password in Settings.")
            TextButton(onClick = { useWords = false }) { Text("Use the password") }
        }
        Column(horizontalAlignment = Alignment.Start) {
            TextButton(onClick = { c.switchVault() }) { Text("Open a different vault") }
        }
    }
}
