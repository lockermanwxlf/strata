# Strata

A cross-platform password vault: Compose Multiplatform UI on Windows, macOS, Linux and Android, with a Rust core bound through UniFFI.

See `CLAUDE.md` for the architecture and security design.

## Prerequisites

- **JDK 17+** with `JAVA_HOME` set (21 recommended)
- **Rust** via rustup. On Windows, install Visual Studio Build Tools with "Desktop development with C++" first.
- **Android builds also need:**
  - Android SDK with an NDK installed (SDK Manager → SDK Tools → NDK), and `ANDROID_HOME` set
  - the Rust Android targets: `rustup target add aarch64-linux-android x86_64-linux-android`
  - cargo-ndk: `cargo install cargo-ndk`

## Run

```sh
./gradlew :desktopApp:run          # desktop
./gradlew :androidApp:installDebug # Android device or emulator
./gradlew :shared:jvmTest          # Kotlin tests against the native core
(cd core && cargo test)            # Rust tests
```

The first desktop run builds the Rust core, generates the Kotlin bindings into `shared/build/generated/uniffi`, and bundles the native library. Later runs only rebuild when Rust sources change.

To use a faster unoptimized Rust build while iterating, set `strata.rust.profile=dev` in `gradle.properties` or pass `-Pstrata.rust.profile=dev`.

## Packaging

`./gradlew :desktopApp:packageDistributionForCurrentOS` produces an installer for the OS you run it on: `.msi` on Windows, `.dmg` on macOS, `.deb`/`.rpm` on Linux. CI (`.github/workflows/build.yml`) builds all of them.
