package dev.lockermanwxlf.strata

import dev.lockermanwxlf.strata.core.ffi.coreVersion

actual fun nativeCoreVersion(): String = coreVersion()
