package dev.lockermanwxlf.strata.android

import android.content.ContentResolver
import android.database.Cursor
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import dev.lockermanwxlf.strata.VaultFolder
import dev.lockermanwxlf.strata.VaultFolderException
import dev.lockermanwxlf.strata.VaultFolderException.Kind
import java.io.ByteArrayOutputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * A vault folder the user picked through the Storage Access Framework, reached
 * through [DocumentsContract] (implementation plan, Phase 11).
 *
 * SAF has no create-exclusive, and providers handle a taken name differently: the
 * device's own storage picks a new name ("x (1).evt"), and cloud providers may keep
 * two files with one name. So [create] checks the name is free, writes the file under
 * a hidden temporary name, renames it into place, and then checks it got exactly that
 * name and is the only file with it. Otherwise it removes its file and reports the
 * name taken. A provider that can't rename gets the file under its final name, so a
 * reader may briefly see it partly written; the core rejects such a file and takes
 * it whole on a later sync, as on a filesystem without hard links.
 *
 * SAF can't make the check and the rename one step. A provider whose rename replaces
 * an existing file could lose a file that appears in between, but each vault file
 * name has a single writer, so only the same device retrying could collide there.
 */
class SafFolder(private val resolver: ContentResolver, private val tree: Uri) : VaultFolder {
    private class Doc(val id: String, val name: String, val isDir: Boolean, val size: Long?)

    private val rootId: String = DocumentsContract.getTreeDocumentId(tree)

    /** Document IDs of the vault's directories, found or created once. */
    private val dirIds = ConcurrentHashMap<String, String>()

    /** Files seen in listings, by vault path. Vault files never change, so this only goes stale by deletion. */
    private val known = ConcurrentHashMap<String, Doc>()

    /** Whether files here can be renamed; learned from the first temporary file. */
    @Volatile private var canRename: Boolean? = null

    override fun list(dir: String): List<String> {
        val id = dirId(dir, create = false) ?: return emptyList()
        val files = children(id).filter { !it.isDir }
        val prefix = if (dir.isEmpty()) "" else "$dir/"
        files.forEach { known[prefix + it.name] = it }
        return files.map { it.name }
    }

    override fun read(path: String, maxLen: Long): ByteArray {
        val doc = find(path) ?: throw missing(path)
        if ((doc.size ?: 0) > maxLen) throw tooLarge(path)
        val input = try {
            resolver.openInputStream(uri(doc.id))
        } catch (_: FileNotFoundException) {
            known.remove(path)
            throw missing(path)
        } ?: throw IOException("can't open $path")
        return input.use { it.readCapped(maxLen) ?: throw tooLarge(path) }
    }

    override fun create(path: String, bytes: ByteArray) {
        val (dir, name) = split(path)
        val parentId = dirId(dir, create = true)!!
        if (file(parentId, name) != null) throw taken(path)

        var doc: Uri? = null
        try {
            if (canRename != false) {
                doc = newFile(parentId, ".strata-${UUID.randomUUID()}.tmp")
                write(doc, bytes)
                if (canRename == null) {
                    canRename = flags(doc) and Document.FLAG_SUPPORTS_RENAME != 0
                }
                if (canRename == true) {
                    doc = DocumentsContract.renameDocument(resolver, doc, name) ?: doc
                } else {
                    delete(doc)
                    doc = null
                }
            }
            if (doc == null) {
                doc = newFile(parentId, name)
                write(doc, bytes)
            }
            // The provider may have settled for another name, or kept a second file.
            val actual = displayName(doc)
            if (actual != name) {
                if (file(parentId, name) != null) throw taken(path)
                throw IOException("the storage provider saved $path as $actual")
            }
            if (children(parentId).count { it.name == name } > 1) throw taken(path)
            doc = null
        } finally {
            doc?.let { runCatching { delete(it) } }
        }
    }

    override fun delete(path: String) {
        val doc = find(path) ?: throw missing(path)
        known.remove(path)
        try {
            delete(uri(doc.id))
        } catch (_: FileNotFoundException) {
            throw missing(path)
        }
    }

    /** Whether the folder can still be reached (the permission may have been revoked). */
    fun holdsVault(): Boolean = runCatching { "strata-vault" in list("") }.getOrDefault(false)

    // ---- DocumentsContract plumbing --------------------------------------------------

    private fun uri(id: String): Uri = DocumentsContract.buildDocumentUriUsingTree(tree, id)

    private fun dirId(dir: String, create: Boolean): String? {
        if (dir.isEmpty()) return rootId
        dirIds[dir]?.let { return it }
        val found = children(rootId).firstOrNull { it.isDir && it.name == dir }?.id
            ?: if (create) {
                val made = DocumentsContract.createDocument(resolver, uri(rootId), Document.MIME_TYPE_DIR, dir)
                    ?: throw IOException("can't create the $dir folder")
                if (displayName(made) != dir) {
                    runCatching { delete(made) }
                    throw IOException("can't create the $dir folder: the name is taken")
                }
                DocumentsContract.getDocumentId(made)
            } else {
                return null
            }
        dirIds[dir] = found
        return found
    }

    private fun find(path: String): Doc? = known[path] ?: split(path).let { (dir, name) ->
        dirId(dir, create = false)?.let { file(it, name) }
    }

    private fun file(parentId: String, name: String): Doc? =
        children(parentId).firstOrNull { !it.isDir && it.name == name }

    private fun children(parentId: String): List<Doc> =
        query(DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId)) { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        Doc(
                            id = c.getString(0),
                            name = c.getString(1),
                            isDir = c.getString(2) == Document.MIME_TYPE_DIR,
                            size = if (c.isNull(3)) null else c.getLong(3),
                        ),
                    )
                }
            }
        }

    private fun displayName(doc: Uri): String? = query(doc) { if (it.moveToFirst()) it.getString(1) else null }

    private fun flags(doc: Uri): Int = query(doc) { if (it.moveToFirst()) it.getInt(4) else 0 }

    /**
     * Runs [read] on a query's results. Cloud providers may answer with a partial
     * listing while they fetch the rest, so this asks again for a few seconds
     * rather than trust one: a file missing from a listing could be overwritten.
     */
    private fun <T> query(uri: Uri, read: (Cursor) -> T): T {
        repeat(LOADING_RETRIES) {
            val cursor = resolver.query(uri, PROJECTION, null, null, null)
                ?: throw IOException("the storage provider didn't answer")
            cursor.use { c ->
                if (!c.extras.getBoolean(DocumentsContract.EXTRA_LOADING)) return read(c)
            }
            Thread.sleep(LOADING_WAIT_MS)
        }
        throw IOException("the storage provider is still loading the folder")
    }

    private fun newFile(parentId: String, name: String): Uri =
        DocumentsContract.createDocument(resolver, uri(parentId), MIME_TYPE, name)
            ?: throw IOException("the storage provider didn't create $name")

    private fun write(doc: Uri, bytes: ByteArray) {
        val out = resolver.openOutputStream(doc, "w") ?: throw IOException("can't write to the folder")
        out.use {
            it.write(bytes)
            it.flush()
            // On the device's own storage, make it durable; providers backed by a pipe can't sync.
            (it as? FileOutputStream)?.let { f -> runCatching { f.fd.sync() } }
        }
    }

    private fun delete(doc: Uri) {
        if (!DocumentsContract.deleteDocument(resolver, doc)) throw IOException("can't delete the file")
    }

    private companion object {
        val PROJECTION = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_SIZE,
            Document.COLUMN_FLAGS,
        )

        /** Keeps providers from guessing a type and adding an extension. */
        const val MIME_TYPE = "application/octet-stream"
        const val LOADING_RETRIES = 20
        const val LOADING_WAIT_MS = 250L

        /** The core passes only `name` or `dir/name` (it checks paths before calling). */
        fun split(path: String): Pair<String, String> =
            path.substringBeforeLast('/', "") to path.substringAfterLast('/')

        fun missing(path: String) = VaultFolderException(Kind.NOT_FOUND, "no such file: $path")
        fun taken(path: String) = VaultFolderException(Kind.ALREADY_EXISTS, "file exists: $path")
        fun tooLarge(path: String) = VaultFolderException(Kind.TOO_LARGE, "file too large: $path")
    }
}

/** Reads to the end, or returns `null` as soon as there are more than [max] bytes. */
private fun InputStream.readCapped(max: Long): ByteArray? {
    val out = ByteArrayOutputStream()
    val buffer = ByteArray(64 * 1024)
    while (true) {
        val n = read(buffer)
        if (n < 0) return out.toByteArray()
        out.write(buffer, 0, n)
        if (out.size() > max) return null
    }
}
