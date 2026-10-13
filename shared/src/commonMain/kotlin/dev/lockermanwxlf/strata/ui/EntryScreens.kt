package dev.lockermanwxlf.strata.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.lockermanwxlf.strata.ConflictCandidate
import dev.lockermanwxlf.strata.EntryDetail
import dev.lockermanwxlf.strata.EntryEdit
import dev.lockermanwxlf.strata.EntrySummary
import dev.lockermanwxlf.strata.StrataCore
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** The fields every new entry offers, in this order. */
private val STANDARD_FIELDS = listOf("title" to false, "username" to false, "password" to true, "url" to false, "notes" to false)

/** Revealed values hide themselves after this long. */
private const val REVEAL_SECONDS = 30L

@Composable
fun EntriesScreen(c: VaultController) {
    val status = c.status
    ScreenFrame(
        "Vault",
        scroll = false,
        actions = {
            TextButton(enabled = !c.busy, onClick = { c.sync() }) { Text("Sync") }
            TextButton(onClick = { c.open(Screen.Settings) }) { Text("Settings") }
            TextButton(onClick = { c.lock() }) { Text("Lock") }
        },
    ) {
        StatusBanners(c)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = c.query,
                onValueChange = { c.query = it },
                label = { Text("Search") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Button(
                enabled = status?.keyRotated == false && status.lostRotation.not() && status.alarm == null,
                onClick = { c.open(Screen.Edit(c.newEntryId(), isNew = true)) },
            ) { Text("New") }
        }
        val shown = c.visibleEntries
        if (shown.isEmpty()) {
            Hint(if (c.entries.none { !it.deleted }) "No entries yet." else "Nothing matches.")
        }
        LazyColumn(Modifier.weight(1f)) {
            items(shown, key = { it.id }) { entry -> EntryRow(entry) { c.open(Screen.Detail(entry.id)) } }
        }
        if (c.trash.isNotEmpty()) {
            TextButton(onClick = { c.open(Screen.Trash) }) { Text("Trash (${c.trash.size})") }
        }
    }
}

/** Warnings about the vault as a whole, above the entry list. */
@Composable
private fun StatusBanners(c: VaultController) {
    val status = c.status ?: return
    var rejoining by remember { mutableStateOf(false) }
    if (status.alarm != null) {
        Banner("Security alarm: the vault is read-only. See Settings.", warning = true)
    }
    if (status.lostRotation) {
        Banner(
            "Another device changed the vault's password at the same moment, and its change won. " +
                "Enter the password set on that device to keep editing here.",
            warning = true,
        ) { Button(onClick = { rejoining = true }) { Text("Enter its password") } }
    } else if (status.keyRotated) {
        Banner(
            "The password was changed on another device. Unlock with the new password to keep editing.",
            warning = true,
        ) { Button(onClick = { c.lock() }) { Text("Unlock again") } }
    }
    if (c.lastSync?.integrityUnverified == true) {
        Banner("Some older files were compacted under a newer key; they're checked once you unlock again.")
    }
    if (status.conflicts > 0) {
        Banner("${status.conflicts} field${plural(status.conflicts)} changed on two devices at once. Open the entries marked ⚠ to choose.")
    }
    if (status.flaggedChanges > 0) {
        Banner("${status.flaggedChanges} change${plural(status.flaggedChanges)} came from a revoked or unrecognized device.", warning = true) {
            TextButton(onClick = { c.open(Screen.Review) }) { Text("Review") }
        }
    }
    if (rejoining) {
        PasswordDialog(
            title = "Use the other device's password",
            explanation = "Your changes made since then are kept and re-sent.",
            confirmLabel = "Continue",
            onDismiss = { rejoining = false },
            onConfirm = {
                rejoining = false
                c.rejoin(it)
            },
        )
    }
}

@Composable
private fun EntryRow(entry: EntrySummary, onClick: () -> Unit) {
    Column(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 10.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(entry.title ?: "(untitled)", style = MaterialTheme.typography.titleMedium)
            if (entry.hasConflict || entry.unansweredDelete) Text("⚠", color = MaterialTheme.colorScheme.error)
        }
        val sub = listOfNotNull(entry.username, entry.tags.takeIf { it.isNotEmpty() }?.joinToString(", ") { "#$it" })
        if (sub.isNotEmpty()) Hint(sub.joinToString("  ·  "))
    }
    HorizontalDivider()
}

@Composable
fun TrashScreen(c: VaultController) {
    var purging by remember { mutableStateOf<String?>(null) }
    ScreenFrame("Trash", onBack = { c.back() }) {
        Hint("Deleted entries stay readable here until you delete them for good.")
        if (c.trash.isEmpty()) Hint("The trash is empty.")
        c.trash.forEach { entry ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(entry.title ?: "(untitled)", modifier = Modifier.weight(1f))
                TextButton(onClick = { c.keep(entry.id) }) { Text("Restore") }
                TextButton(onClick = { purging = entry.id }) { Text("Delete for good") }
            }
            HorizontalDivider()
        }
    }
    purging?.let { id ->
        PasswordDialog(
            title = "Delete for good?",
            explanation = "This removes every trace of the entry from the vault folder and changes the vault key. " +
                "Copies someone already made of the files can't be taken back.",
            confirmLabel = "Delete for good",
            onDismiss = { purging = null },
            onConfirm = {
                purging = null
                c.purge(id, it)
            },
        )
    }
}

@Composable
fun DetailScreen(c: VaultController, id: String) {
    var detail by remember { mutableStateOf<EntryDetail?>(null) }
    // Reload whenever the entries change (an edit, a sync).
    LaunchedEffect(id, c.entries) { detail = runCatching { c.entry(id) }.getOrNull() }
    // Revealed values, as display strings: the on-screen exception. Hidden on a timer
    // and dropped when the screen goes.
    val revealed = remember { mutableStateMapOf<String, String>() }
    DisposableEffect(Unit) { onDispose { revealed.clear() } }
    val scope = rememberCoroutineScope()
    var deleting by remember { mutableStateOf(false) }
    val d = detail
    val writable = c.status?.let { !it.keyRotated && !it.lostRotation && it.alarm == null } == true

    ScreenFrame(
        d?.fields?.firstOrNull { it.name == "title" }?.value ?: "Entry",
        onBack = { c.back() },
        actions = {
            if (d != null && !d.deleted && writable) {
                TextButton(onClick = { c.open(Screen.Edit(id, isNew = false)) }) { Text("Edit") }
                TextButton(onClick = { deleting = true }) { Text("Delete") }
            }
        },
    ) {
        if (d == null) {
            Hint("This entry isn't in the vault.")
            return@ScreenFrame
        }
        if (d.deleted) {
            Banner("This entry is in the trash.") { TextButton(onClick = { c.keep(id) }) { Text("Restore") } }
        } else if (d.unansweredDelete) {
            Banner("This entry was deleted on another device while it was being edited here. Keep it?", warning = true) {
                Button(onClick = { c.keep(id) }) { Text("Keep") }
                OutlinedButton(onClick = { c.delete(id) }) { Text("Delete") }
            }
        }
        d.fields.sortedBy { order(it.name) }.forEach { field ->
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Hint(field.name)
                when {
                    field.conflictCandidates > 0 -> Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "⚠ ${field.conflictCandidates} different values",
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.weight(1f),
                        )
                        if (writable) Button(onClick = { c.open(Screen.Resolve(id, field.name)) }) { Text("Choose") }
                    }
                    field.secret -> Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            revealed[field.name] ?: "••••••••",
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(onClick = {
                            if (revealed.remove(field.name) == null) {
                                scope.launch {
                                    val bytes = c.reveal(id, field.name) ?: return@launch
                                    revealed[field.name] = bytes.decodeToString()
                                    bytes.fill(0)
                                    delay(REVEAL_SECONDS * 1000)
                                    revealed.remove(field.name)
                                }
                            }
                        }) { Text(if (field.name in revealed) "Hide" else "Show") }
                        TextButton(onClick = { c.copy(id, field.name) }) { Text("Copy") }
                    }
                    else -> Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(field.value.orEmpty(), modifier = Modifier.weight(1f))
                        TextButton(onClick = { c.copy(id, field.name) }) { Text("Copy") }
                    }
                }
            }
        }
        if (d.tags.isNotEmpty()) Hint(d.tags.joinToString("  ") { "#$it" })
    }
    if (deleting) {
        ConfirmDialog(
            title = "Move to the trash?",
            text = "You can restore it from the trash later.",
            confirmLabel = "Delete",
            onDismiss = { deleting = false },
            onConfirm = {
                deleting = false
                c.delete(id)
            },
        )
    }
}

/** Standard fields first, in their usual order, then the rest by name. */
private fun order(name: String): String {
    val i = STANDARD_FIELDS.indexOfFirst { it.first == name }
    return if (i >= 0) "0$i" else "1$name"
}

/** One field in the editor. */
private class FieldDraft(
    val name: String,
    val secret: Boolean,
    /** A non-secret field's value when the editor opened. */
    val original: String?,
    /** The field had a value (secret or not) when the editor opened. */
    val existed: Boolean,
) {
    val state = TextFieldState(original.orEmpty())
    var removed by mutableStateOf(false)

    /** For secret fields: the user chose to type a new value. New entries always do. */
    var replacing by mutableStateOf(!existed)
}

@Composable
fun EditScreen(c: VaultController, id: String, isNew: Boolean) {
    var loaded by remember { mutableStateOf(isNew) }
    val drafts = remember { mutableStateListOf<FieldDraft>() }
    val tags = remember { TextFieldState() }
    var originalTags by remember { mutableStateOf(emptyList<String>()) }
    LaunchedEffect(id) {
        val detail = if (isNew) null else c.entry(id)
        val present = detail?.fields.orEmpty()
        STANDARD_FIELDS.forEach { (name, secret) ->
            val f = present.firstOrNull { it.name == name }
            drafts += FieldDraft(name, f?.secret ?: secret, f?.value, existed = f != null)
        }
        present.filter { f -> STANDARD_FIELDS.none { it.first == f.name } }.forEach {
            drafts += FieldDraft(it.name, it.secret, it.value, existed = true)
        }
        originalTags = detail?.tags.orEmpty()
        tags.edit { replace(0, length, originalTags.joinToString(", ")) }
        loaded = true
    }
    // Typed secrets go with the screen.
    DisposableEffect(Unit) { onDispose { drafts.filter { it.secret }.forEach { it.state.clearText() } } }
    var newName by remember { mutableStateOf("") }
    var newSecret by remember { mutableStateOf(false) }

    ScreenFrame(
        if (isNew) "New entry" else "Edit entry",
        onBack = { c.back() },
        actions = {
            TextButton(enabled = loaded && !c.busy, onClick = {
                c.save(edits(id, drafts, tags, originalTags))
            }) { Text("Save") }
        },
    ) {
        if (!loaded) return@ScreenFrame
        drafts.filterNot { it.removed }.forEach { draft -> FieldEditor(draft) }
        HorizontalDivider()
        SectionTitle("Add a field")
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = newName,
                onValueChange = { newName = it },
                label = { Text("Field name") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Checkbox(checked = newSecret, onCheckedChange = { newSecret = it })
            Text("Secret")
            Button(
                enabled = newName.isNotBlank() && drafts.none { it.name == newName.trim() && !it.removed },
                onClick = {
                    drafts.removeAll { it.name == newName.trim() }
                    drafts += FieldDraft(newName.trim(), newSecret, null, existed = false)
                    newName = ""
                    newSecret = false
                },
            ) { Text("Add") }
        }
        OutlinedTextField(state = tags, label = { Text("Tags, separated by commas") }, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun FieldEditor(draft: FieldDraft) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Column(Modifier.weight(1f)) {
            when {
                !draft.secret -> OutlinedTextField(
                    state = draft.state,
                    label = { Text(draft.name) },
                    modifier = Modifier.fillMaxWidth(),
                )
                !draft.replacing -> Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("${draft.name}: unchanged", modifier = Modifier.weight(1f))
                    TextButton(onClick = { draft.replacing = true }) { Text("Change") }
                }
                else -> Row(verticalAlignment = Alignment.CenterVertically) {
                    PasswordField(draft.state, draft.name, Modifier.weight(1f))
                    TextButton(onClick = { draft.state.setAscii(StrataCore.generatePassword(20, symbols = true)) }) {
                        Text("Generate")
                    }
                }
            }
        }
        if (draft.name != "title") TextButton(onClick = { draft.removed = true }) { Text("Remove") }
    }
}

/** The edits that turn the entry as it was into what the editor holds. */
private fun edits(id: String, drafts: List<FieldDraft>, tags: TextFieldState, originalTags: List<String>): List<EntryEdit> {
    val out = mutableListOf<EntryEdit>()
    for (d in drafts) {
        when {
            d.removed -> if (d.existed) out += EntryEdit.SetField(id, d.name, null, d.secret)
            d.secret -> if (d.replacing && !d.state.isEmpty) out += EntryEdit.SetField(id, d.name, d.state.takeUtf8(), secret = true)
            else -> {
                // Non-secret values are ordinary text.
                val text = d.state.text.toString()
                when {
                    text.isEmpty() && d.existed -> out += EntryEdit.SetField(id, d.name, null)
                    text.isNotEmpty() && text != d.original -> out += EntryEdit.SetField(id, d.name, text.encodeToByteArray())
                }
            }
        }
    }
    val newTags = tags.text.toString().split(',').map { it.trim() }.filter { it.isNotEmpty() }.distinct()
    (newTags - originalTags.toSet()).forEach { out += EntryEdit.AddTag(id, it) }
    (originalTags - newTags.toSet()).forEach { out += EntryEdit.RemoveTag(id, it) }
    return out
}

@Composable
fun ResolveScreen(c: VaultController, id: String, field: String) {
    var candidates by remember { mutableStateOf<List<ConflictCandidate>>(emptyList()) }
    LaunchedEffect(id, field) { candidates = c.conflictCandidates(id, field) }
    DisposableEffect(Unit) { onDispose { candidates.forEach { it.value?.fill(0) } } }
    val shown = remember { mutableStateMapOf<Int, String>() }
    val typed = rememberTextFieldState()

    ScreenFrame("Choose a value", onBack = { c.back() }) {
        Text("“$field” was changed on two devices at the same time. Pick the value to keep, or type a new one.")
        candidates.forEachIndexed { i, candidate ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Hint("From ${candidate.deviceName ?: "an unknown device"}")
                    val value = candidate.value
                    if (value == null) {
                        Text("Removed the field")
                    } else {
                        Text(shown[i] ?: "••••••••", fontFamily = FontFamily.Monospace)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (value != null) {
                            TextButton(onClick = {
                                if (shown.remove(i) == null) shown[i] = value.decodeToString()
                            }) { Text(if (i in shown) "Hide" else "Show") }
                        }
                        Button(onClick = { c.resolve(id, field, value?.copyOf()) }) { Text("Keep this") }
                    }
                }
            }
        }
        SectionTitle("Or a new value")
        PasswordField(typed, field)
        Button(enabled = !typed.isEmpty, onClick = { c.resolve(id, field, typed.takeUtf8()) }) { Text("Use this") }
    }
}

private fun plural(n: Int) = if (n == 1) "" else "s"
