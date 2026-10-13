package dev.lockermanwxlf.strata

import dev.lockermanwxlf.strata.core.ffi.PolicyException
import dev.lockermanwxlf.strata.core.ffi.ProtectorCaps
import dev.lockermanwxlf.strata.core.ffi.ProtectorStrength
import dev.lockermanwxlf.strata.core.ffi.SlotScope
import dev.lockermanwxlf.strata.core.ffi.Vault
import dev.lockermanwxlf.strata.core.ffi.checkSlotPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Exercises the real native library through the generated bindings. */
class CoreBindingsTest {
    private val hardware = ProtectorCaps(hardwareBacked = true, rateLimited = true, userPresence = true)

    @Test
    fun nativeLibraryLoads() {
        assertTrue(StrataCore.version().isNotBlank())
    }

    @Test
    fun weakProtectorCannotSync() {
        assertFailsWith<PolicyException.WeakProtectorCannotSync> {
            checkSlotPolicy(ProtectorStrength.WEAK, SlotScope.SYNCED, hardware)
        }
    }

    @Test
    fun weakLocalProtectorAllowedOnRateLimitedHardware() {
        checkSlotPolicy(ProtectorStrength.WEAK, SlotScope.LOCAL, hardware)
    }

    /**
     * A structural check on the generated API: nothing on the vault object returns a
     * `String`, so no call can hand out a secret as one. Values come back as
     * `ByteArray`s the caller can wipe.
     */
    @Test
    fun noVaultCallReturnsAString() {
        val stringReturning = Vault::class.java.declaredMethods
            .filter { it.returnType == String::class.java && it.name != "toString" }
            .map { it.name }
        assertEquals(emptyList(), stringReturning)
        assertEquals(
            ByteArray::class.java,
            Vault::class.java.getMethod("reveal", String::class.java, String::class.java).returnType,
        )
    }
}
