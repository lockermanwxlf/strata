import javax.inject.Inject
import org.gradle.process.ExecOperations

// Android entry point. With AGP 9, an application module can't also be a KMP module,
// so the UI and bindings live in :shared and this module only packages the app.
// AGP 9 has built-in Kotlin support; don't apply org.jetbrains.kotlin.android.

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

/** Cross-compiles the Rust core for Android ABIs with cargo-ndk, laid out as jniLibs/<abi>/. */
abstract class CargoNdkBuild : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val rustSources: ConfigurableFileCollection

    @get:Internal
    abstract val coreDir: DirectoryProperty

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val platformApi: Property<Int>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Inject
    abstract val execOps: ExecOperations

    @TaskAction
    fun build() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        execOps.exec {
            workingDir = coreDir.get().asFile
            commandLine(
                buildList {
                    addAll(listOf("cargo", "ndk"))
                    abis.get().forEach { addAll(listOf("-t", it)) }
                    addAll(listOf("-P", platformApi.get().toString(), "-o", out.absolutePath))
                    addAll(listOf("build", "--release", "-p", "strata-core"))
                },
            )
        }
    }
}

// arm64-v8a: real phones. x86_64: the emulator. Add "armeabi-v7a" for old 32-bit devices.
val androidAbis = listOf("arm64-v8a", "x86_64")

val cargoNdkBuild by tasks.registering(CargoNdkBuild::class) {
    group = "rust"
    description = "Builds the Rust core for Android with cargo-ndk."
    coreDir.set(rootProject.layout.projectDirectory.dir("core"))
    rustSources.from(
        fileTree(rootProject.layout.projectDirectory.dir("core")) {
            include("**/*.rs", "**/Cargo.toml", "Cargo.lock", "**/uniffi.toml")
            exclude("target/**")
        },
    )
    abis.set(androidAbis)
    platformApi.set(libs.versions.android.minSdk.get().toInt())
    outputDir.set(layout.buildDirectory.dir("generated/rust/jniLibs"))
}

android {
    namespace = "dev.lockermanwxlf.strata.android"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "dev.lockermanwxlf.strata"
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            abiFilters += androidAbis
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    buildTypes {
        // Screenshot blocking (FLAG_SECURE) follows the build type, so a release build can't ship without it.
        debug {
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", "true")
        }
        release {
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoNdkBuild, CargoNdkBuild::outputDir)
    }
}

dependencies {
    implementation(project(":shared"))
    implementation(libs.androidx.activity.compose)
}
