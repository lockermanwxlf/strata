package dev.lockermanwxlf.strata.desktop

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * On Windows, a copied secret must carry the formats that keep it out of clipboard
 * history and the cloud clipboard. Checked from outside the JVM, with the Win32 API.
 */
class ClipboardTest {
    private val windows = System.getProperty("os.name").startsWith("Windows")

    @Test
    fun copiedSecretsOptOutOfClipboardHistory() {
        if (!windows) return
        val clipboard = AwtClipboard()
        clipboard.copy("not a real secret".encodeToByteArray())
        try {
            val formats = clipboardFormatNames()
            for (name in listOf("ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard")) {
                assertTrue(name in formats, "$name missing from $formats")
            }
        } finally {
            clipboard.clearIfStillOurs()
        }
    }

    /** The registered format names on the clipboard, read by another process. */
    private fun clipboardFormatNames(): List<String> {
        val script = """
            Add-Type -TypeDefinition @'
            using System; using System.Runtime.InteropServices; using System.Text;
            public static class Clip {
              [DllImport("user32.dll")] static extern bool OpenClipboard(IntPtr h);
              [DllImport("user32.dll")] static extern bool CloseClipboard();
              [DllImport("user32.dll")] static extern uint EnumClipboardFormats(uint f);
              [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClipboardFormatName(uint f, StringBuilder s, int n);
              public static string Names() {
                for (int i = 0; i < 50 && !OpenClipboard(IntPtr.Zero); i++) System.Threading.Thread.Sleep(20);
                var sb = new StringBuilder(); uint f = 0;
                while ((f = EnumClipboardFormats(f)) != 0) {
                  var n = new StringBuilder(256);
                  if (GetClipboardFormatName(f, n, 256) > 0) sb.Append(n).Append('\n');
                }
                CloseClipboard(); return sb.ToString();
              }
            }
            '@
            [Clip]::Names()
        """.trimIndent()
        val encoded = Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE))
        val process = ProcessBuilder("powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        process.waitFor()
        return output.lines().map { it.trim() }.filter { it.isNotEmpty() }
    }
}
