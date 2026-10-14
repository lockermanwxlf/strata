package dev.lockermanwxlf.strata.ui

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import dev.lockermanwxlf.strata.PickedFile
import dev.lockermanwxlf.strata.StrataCore
import kotlinx.coroutines.launch

@Composable
fun ImportKeePassScreen(c: VaultController) {
    var file by remember { mutableStateOf<PickedFile?>(null) }
    var keyfile by remember { mutableStateOf<PickedFile?>(null) }
    val password = rememberTextFieldState()
    val scope = rememberCoroutineScope()
    // A key file is a secret; it goes with the screen if it wasn't used.
    DisposableEffect(Unit) { onDispose { keyfile?.bytes?.fill(0) } }

    ScreenFrame("Import from KeePass", onBack = { c.back() }) {
        Text(
            "Adds the entries of a KeePass file (.kdbx) to this vault as new entries. Nothing already " +
                "in the vault changes. Older versions of entries and the recycle bin stay behind.",
        )
        OutlinedButton(onClick = { scope.launch { c.pickFile()?.let { file = it } } }, modifier = Modifier.fillMaxWidth()) {
            Text(file?.let { "File: ${it.name}" } ?: "Choose the KeePass file")
        }
        PasswordField(password, "The KeePass file's password")
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(
                onClick = {
                    scope.launch {
                        c.pickFile()?.let {
                            keyfile?.bytes?.fill(0)
                            keyfile = it
                        }
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(keyfile?.let { "Key file: ${it.name}" } ?: "Add a key file (only if it uses one)") }
            if (keyfile != null) {
                TextButton(onClick = {
                    keyfile?.bytes?.fill(0)
                    keyfile = null
                }) { Text("Remove") }
            }
        }
        Button(
            enabled = file != null && !c.busy,
            onClick = {
                val chosen = file ?: return@Button
                val key = keyfile
                keyfile = null
                c.importKdbx(chosen, password.takeUtf8(), key)
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Import") }
    }
}

@Composable
fun ExportKeePassScreen(c: VaultController) {
    val password = rememberTextFieldState()
    val confirm = rememberTextFieldState()
    var weak by remember { mutableStateOf(false) }
    var acceptWeak by remember { mutableStateOf(false) }
    var mismatch by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    ScreenFrame("Export to KeePass", onBack = { c.back() }) {
        Text("Writes every entry, except those in the trash, to a KeePass file (.kdbx) that KeePass and KeePassXC can open.")
        Banner(
            "The file is protected only by the password you choose here, not by Strata. Anyone with " +
                "the file and that password can read everything in it. Delete it when you're done.",
            warning = true,
        )
        PasswordField(password, "A password for the file")
        PasswordField(confirm, "Repeat it")
        if (mismatch) Text("The passwords don't match.", color = MaterialTheme.colorScheme.error)
        if (weak) {
            Banner("This password looks easy to guess.", warning = true) {
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
                    weak = StrataCore.passwordStrength(password.text.utf8()).warn
                    if (weak && !acceptWeak) return@launch
                    confirm.takeUtf8().fill(0)
                    c.exportKdbx(password.takeUtf8())
                }
            },
        ) { Text("Export") }
    }
}
