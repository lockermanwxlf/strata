package dev.lockermanwxlf.strata.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.lockermanwxlf.strata.Alarm
import dev.lockermanwxlf.strata.DeviceInfo
import dev.lockermanwxlf.strata.StrataCore
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(c: VaultController) {
    var newRecovery by remember { mutableStateOf(false) }
    var choosingPin by remember { mutableStateOf(false) }
    val status = c.status
    ScreenFrame("Settings", onBack = { c.back() }) {
        c.folder?.let { Hint("Vault folder: $it") }
        c.lastSync?.let { s ->
            Hint(
                "Last sync: ${s.applied} change${if (s.applied == 1) "" else "s"} received, ${s.uploaded} sent" +
                    (if (s.held > 0) ", ${s.held} waiting" else "") +
                    (if (s.rejected > 0) ", ${s.rejected} unreadable file${if (s.rejected == 1) "" else "s"} set aside" else ""),
            )
        }
        if (status?.alarm != null) {
            Banner(alarmText(status.alarm), warning = true)
        }
        SectionTitle("Security")
        Button(onClick = { c.open(Screen.ChangePassword) }, modifier = Modifier.fillMaxWidth()) { Text("Change password") }
        OutlinedButton(onClick = { newRecovery = true }, modifier = Modifier.fillMaxWidth()) { Text("New recovery words") }
        OutlinedButton(onClick = { c.open(Screen.Devices) }, modifier = Modifier.fillMaxWidth()) { Text("Devices") }
        if ((status?.flaggedChanges ?: 0) > 0 || (status?.suspectDevices ?: 0) > 0) {
            OutlinedButton(onClick = { c.open(Screen.Review) }, modifier = Modifier.fillMaxWidth()) {
                Text("Review flagged changes")
            }
        }
        c.deviceProtector?.let { device ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Unlock with ${device.label}")
                    Hint("On this device only. The password still works everywhere.")
                }
                Switch(
                    checked = c.deviceUnlockEnabled,
                    enabled = !c.busy,
                    onCheckedChange = { on ->
                        if (on && device.needsPin) choosingPin = true else c.setDeviceUnlock(on)
                    },
                )
            }
        }
        if (choosingPin) PinDialog(onDismiss = { choosingPin = false }) {
            choosingPin = false
            c.setDeviceUnlock(true, it)
        }
        HorizontalDivider()
        SectionTitle("Vault")
        OutlinedButton(onClick = { c.open(Screen.Trash) }, modifier = Modifier.fillMaxWidth()) { Text("Trash") }
        OutlinedButton(onClick = { c.switchVault() }, modifier = Modifier.fillMaxWidth()) { Text("Open a different vault") }
        Hint(
            "Locks after ${c.idleTimeout.inWholeMinutes} minutes without input. " +
                "Copied secrets are cleared from the clipboard after ${c.clipboardTimeout.inWholeSeconds} seconds.",
        )
        Hint("Strata ${StrataCore.version()}")
    }
    if (newRecovery) {
        PasswordDialog(
            title = "New recovery words",
            explanation = "The current recovery words stop working. This changes the vault key, so other " +
                "devices ask for the password once.",
            confirmLabel = "Continue",
            onDismiss = { newRecovery = false },
            onConfirm = {
                newRecovery = false
                c.replaceRecoveryKey(it)
            },
        )
    }
}

@Composable
fun ChangePasswordScreen(c: VaultController) {
    val password = rememberTextFieldState()
    val confirm = rememberTextFieldState()
    var weak by remember { mutableStateOf(false) }
    var acceptWeak by remember { mutableStateOf(false) }
    var mismatch by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    ScreenFrame("Change password", onBack = { c.back() }) {
        Text(
            "This changes the vault key. Other devices keep what they have but can't write until " +
                "they unlock with the new password.",
        )
        PasswordField(password, "New password")
        PasswordField(confirm, "Repeat the new password")
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
                    c.changePassword(password.takeUtf8())
                }
            },
        ) { Text("Change password") }
    }
}

@Composable
fun DevicesScreen(c: VaultController) {
    var devices by remember { mutableStateOf<List<DeviceInfo>>(emptyList()) }
    LaunchedEffect(c.entries, c.status) { devices = c.devices() }
    var revoking by remember { mutableStateOf<DeviceInfo?>(null) }
    var renaming by remember { mutableStateOf(false) }
    var name by remember { mutableStateOf("") }

    ScreenFrame("Devices", onBack = { c.back() }) {
        Hint("Every device that has written to this vault. Revoke one that's lost or no longer yours.")
        devices.forEach { d ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(d.name + if (d.thisDevice) " (this device)" else "")
                    val notes = listOfNotNull(
                        "revoked".takeIf { d.retired },
                        "unrecognized: registered with an old key".takeIf { d.suspect },
                    )
                    if (notes.isNotEmpty()) Hint(notes.joinToString(", "))
                }
                if (d.thisDevice) {
                    TextButton(onClick = {
                        name = d.name
                        renaming = true
                    }) { Text("Rename") }
                } else if (!d.retired) {
                    TextButton(onClick = { revoking = d }) { Text("Revoke") }
                }
            }
            HorizontalDivider()
        }
        if (renaming) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("This device's name") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                Button(enabled = name.isNotBlank(), onClick = {
                    renaming = false
                    c.renameDevice(name.trim())
                }) { Text("Save") }
            }
        }
    }
    revoking?.let { d ->
        PasswordDialog(
            title = "Revoke ${d.name}?",
            explanation = "It won't be able to read anything written from now on, and anything it changes " +
                "afterwards is flagged for review. If it may know the password, change the password too.",
            confirmLabel = "Revoke",
            onDismiss = { revoking = null },
            onConfirm = {
                revoking = null
                c.revokeDevice(d.clientId, it)
            },
        )
    }
}

@Composable
fun ReviewScreen(c: VaultController) {
    val status = c.status
    ScreenFrame("Review changes", onBack = { c.back() }) {
        Text(
            "${status?.flaggedChanges ?: 0} change${if (status?.flaggedChanges == 1) "" else "s"} came from a " +
                "revoked device, or from a device that appeared under an old key after a key change. " +
                "Either can mean someone with an old copy of the key is writing to the vault.",
        )
        Text("Reverting restores what the entries held without those changes, as new changes from this device.")
        Button(enabled = !c.busy, onClick = { c.revertFlagged() }, modifier = Modifier.fillMaxWidth()) {
            Text("Revert them all")
        }
        Hint("Also change the password if a device was lost, so a copy of the old key can't open new data.")
    }
}

/** Shown over everything when the vault raises an alarm, until acknowledged. */
@Composable
fun AlarmScreen(c: VaultController, alarm: Alarm) {
    ScreenFrame("Security alarm") {
        Banner(alarmText(alarm), warning = true)
        Text(
            "The vault is read-only on this device until this is sorted out. Don't add new secrets. " +
                "Check the vault folder's history (backups, sync conflicts), and compare with your other devices.",
        )
        Button(onClick = { c.acknowledgeAlarm() }, modifier = Modifier.fillMaxWidth()) { Text("Keep reading") }
        OutlinedButton(onClick = { c.lock() }, modifier = Modifier.fillMaxWidth()) { Text("Lock") }
    }
}

private fun alarmText(alarm: Alarm) = when (alarm) {
    Alarm.ROLLBACK -> "Files this device had already seen are missing or older than before. Someone may have " +
        "restored an old copy of the vault folder to hide changes."
    Alarm.FORK -> "Two different versions of the same history exist. A device may have been cloned, or the " +
        "files were tampered with."
    Alarm.SLOT_SUBSTITUTION -> "A key file opens a different key than this vault's. Someone may be trying to " +
        "get your devices to encrypt under a key they know."
    Alarm.FORGERY -> "A file carries a signature that doesn't match the device it claims to come from."
}

/** The PIN for a TPM-backed unlock, typed twice. The TPM locks out repeated wrong guesses. */
@Composable
private fun PinDialog(onDismiss: () -> Unit, onConfirm: (ByteArray) -> Unit) {
    val pin = rememberTextFieldState()
    val repeat = rememberTextFieldState()
    var problem by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Choose a PIN") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("The TPM in this computer keeps the key, and locks out repeated wrong PINs.")
                PasswordField(pin, "PIN")
                PasswordField(repeat, "Repeat the PIN")
                problem?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                problem = when {
                    pin.text.length < MIN_PIN_LENGTH -> "Use at least $MIN_PIN_LENGTH characters."
                    !pin.sameTextAs(repeat) -> "The PINs don't match."
                    else -> null
                }
                if (problem == null) {
                    repeat.takeUtf8().fill(0)
                    onConfirm(pin.takeUtf8())
                }
            }) { Text("Turn on") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private const val MIN_PIN_LENGTH = 4
