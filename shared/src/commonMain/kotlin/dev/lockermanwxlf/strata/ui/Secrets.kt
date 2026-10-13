package dev.lockermanwxlf.strata.ui

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText

/**
 * Takes what was typed into a password field as UTF-8 bytes, then clears the field.
 * The bytes are encoded straight from the field's characters, never through a
 * `String`. The field's own buffer belongs to Compose and can't be wiped; clearing
 * it right away is what's possible.
 */
fun TextFieldState.takeUtf8(): ByteArray {
    val bytes = text.utf8()
    clearText()
    return bytes
}

/** Whether the field is empty, without copying its contents. */
val TextFieldState.isEmpty: Boolean get() = text.isEmpty()

/** Compares two password fields without building strings. */
fun TextFieldState.sameTextAs(other: TextFieldState): Boolean {
    val a = text
    val b = other.text
    if (a.length != b.length) return false
    var diff = 0
    for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
    return diff == 0
}

/** Replaces the field's contents with [bytes] (ASCII, e.g. a generated password), then wipes them. */
fun TextFieldState.setAscii(bytes: ByteArray) {
    val chars = CharArray(bytes.size) { (bytes[it].toInt() and 0x7f).toChar() }
    bytes.fill(0)
    edit { replace(0, length, CharArraySequence(chars)) }
    chars.fill('\u0000')
}

private class CharArraySequence(private val chars: CharArray) : CharSequence {
    override val length: Int get() = chars.size
    override fun get(index: Int): Char = chars[index]
    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence =
        CharArraySequence(chars.copyOfRange(startIndex, endIndex))
}

/** UTF-8 encoding of [CharSequence], with no `String` in between. Lone surrogates become U+FFFD. */
internal fun CharSequence.utf8(): ByteArray {
    var size = 0
    forEachCodePoint { size += utf8Length(it) }
    val out = ByteArray(size)
    var i = 0
    forEachCodePoint { cp ->
        when {
            cp < 0x80 -> out[i++] = cp.toByte()
            cp < 0x800 -> {
                out[i++] = (0xc0 or (cp shr 6)).toByte()
                out[i++] = (0x80 or (cp and 0x3f)).toByte()
            }
            cp < 0x10000 -> {
                out[i++] = (0xe0 or (cp shr 12)).toByte()
                out[i++] = (0x80 or ((cp shr 6) and 0x3f)).toByte()
                out[i++] = (0x80 or (cp and 0x3f)).toByte()
            }
            else -> {
                out[i++] = (0xf0 or (cp shr 18)).toByte()
                out[i++] = (0x80 or ((cp shr 12) and 0x3f)).toByte()
                out[i++] = (0x80 or ((cp shr 6) and 0x3f)).toByte()
                out[i++] = (0x80 or (cp and 0x3f)).toByte()
            }
        }
    }
    return out
}

private fun utf8Length(cp: Int) = when {
    cp < 0x80 -> 1
    cp < 0x800 -> 2
    cp < 0x10000 -> 3
    else -> 4
}

private inline fun CharSequence.forEachCodePoint(action: (Int) -> Unit) {
    var i = 0
    while (i < length) {
        val c = this[i]
        if (c.isHighSurrogate() && i + 1 < length && this[i + 1].isLowSurrogate()) {
            action(0x10000 + ((c.code - 0xd800) shl 10) + (this[i + 1].code - 0xdc00))
            i += 2
        } else {
            action(if (c.isSurrogate()) 0xfffd else c.code)
            i += 1
        }
    }
}
