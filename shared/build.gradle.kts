// Shared UI + the Kotlin side of the Rust core.
//
// Build flow for the JVM (desktop) target:
//   cargoBuildHost       cargo builds core/strata-core as a native library for this machine
//   generateUniffiKotlin uniffi-bindgen reads that library and writes the Kotlin bindings
//   bundleHostNative     copies the library into a resource folder JNA can load it from
// Android packages its .so files in :androidApp (cargo-ndk), but reuses the same bindings.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.compose.multiplatform)
}

val coreDir = rootProject.layout.projectDirectory.dir("core")
val rustProfile = providers.gradleProperty("strata.rust.profile").getOrElse("release")
val rustTargetSubdir = if (rustProfile == "dev") "debug" else rustProfile

// Library file name and JNA resource prefix for the machine running the build.
val hostOs: String = System.getProperty("os.name").lowercase()
val hostArch = when (System.getProperty("os.arch").lowercase()) {
    "aarch64", "arm64" -> "aarch64"
    else -> "x86-64"
}
val (hostLibFile, jnaResourceDir) = when {
    hostOs.contains("win") -> "strata_core.dll" to "win32-$hostArch"
    hostOs.contains("mac") -> "libstrata_core.dylib" to "darwin-$hostArch"
    else -> "libstrata_core.so" to "linux-$hostArch"
}
val hostLib = coreDir.file("target/$rustTargetSubdir/$hostLibFile")

val rustSources = fileTree(coreDir) {
    include("**/*.rs", "**/Cargo.toml", "Cargo.lock", "**/uniffi.toml")
    exclude("target/**")
}

val cargoBuildHost by tasks.registering(Exec::class) {
    group = "rust"
    description = "Builds the Rust core for this machine."
    workingDir = coreDir.asFile
    commandLine("cargo", "build", "--profile", rustProfile, "-p", "strata-core")
    inputs.files(rustSources).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.property("profile", rustProfile)
    outputs.file(hostLib)
}

val generateUniffiKotlin by tasks.registering(Exec::class) {
    group = "rust"
    description = "Generates Kotlin bindings for the Rust core with UniFFI."
    dependsOn(cargoBuildHost)
    val outDir = layout.buildDirectory.dir("generated/uniffi/kotlin")
    workingDir = coreDir.asFile
    inputs.file(hostLib)
    outputs.dir(outDir)
    doFirst { outDir.get().asFile.deleteRecursively() }
    commandLine(
        "cargo", "run", "--quiet", "-p", "uniffi-bindgen", "--",
        "generate", hostLib.asFile.absolutePath,
        "--language", "kotlin",
        "--out-dir", outDir.get().asFile.absolutePath,
        "--no-format",
    )
}

val bundleHostNative by tasks.registering(Copy::class) {
    group = "rust"
    description = "Places the host native library where JNA looks for it on the classpath."
    from(cargoBuildHost) { into(jnaResourceDir) }
    into(layout.buildDirectory.dir("generated/uniffi/resources"))
}

// The Kotlin side of the bindings (NativeVault.kt). Like the generated bindings it
// uses JNA, so it compiles into each JVM-based target rather than into commonMain.
val jnaSources = layout.projectDirectory.dir("src/jna/kotlin")

kotlin {
    jvm()

    android {
        namespace = "dev.lockermanwxlf.strata.shared"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.compose.runtime)
                implementation(libs.compose.foundation)
                implementation(libs.compose.ui)
                implementation(libs.compose.material3)
                implementation(libs.kotlinx.coroutines.core)
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
        jvmTest {
            dependencies {
                // Skia for this OS, so tests can render screens to images (ScreenshotTest).
                implementation(compose.desktop.currentOs)
            }
        }
        jvmMain {
            // The bindings use JNA and java.nio, so they compile per JVM-based target
            // rather than in commonMain.
            kotlin.srcDir(generateUniffiKotlin)
            kotlin.srcDir(jnaSources)
            resources.srcDir(bundleHostNative)
            dependencies {
                implementation(libs.jna)
            }
        }
        androidMain {
            kotlin.srcDir(generateUniffiKotlin)
            kotlin.srcDir(jnaSources)
            dependencies {
                // The AAR ships libjnidispatch.so for each Android ABI.
                implementation("net.java.dev.jna:jna:${libs.versions.jna.get()}@aar")
                implementation(libs.kotlinx.coroutines.android)
            }
        }
    }
}

// JNA loads the core via System.load, which newer JDKs restrict unless native access is enabled.
tasks.named<Test>("jvmTest") {
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
