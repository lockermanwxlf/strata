package dev.lockermanwxlf.strata

import dev.lockermanwxlf.strata.core.ffi.PolicyException
import dev.lockermanwxlf.strata.core.ffi.ProtectorCaps
import dev.lockermanwxlf.strata.core.ffi.ProtectorStrength
import dev.lockermanwxlf.strata.core.ffi.SlotScope
import dev.lockermanwxlf.strata.core.ffi.checkSlotPolicy
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Exercises the real native library through the generated bindings. */
class CoreBindingsTest {
    private val hardware = ProtectorCaps(hardwareBacked = true, rateLimited = true, userPresence = true)

    @Test
    fun nativeLibraryLoads() {
        assertTrue(nativeCoreVersion().isNotBlank())
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
}
