package dev.lockermanwxlf.strata

/**
 * Common-code entry points into the Rust core.
 *
 * The UniFFI bindings (package `dev.lockermanwxlf.strata.core.ffi`) are JVM/Android-only
 * because they use JNA, so common code reaches the core through these declarations.
 * Keep this surface coarse-grained: one call per user-level operation, not per field.
 */
expect fun nativeCoreVersion(): String
