import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.compose.multiplatform)
}

dependencies {
    implementation(project(":shared"))
    implementation(compose.desktop.currentOs)
    implementation(libs.kotlinx.coroutines.swing)
    testImplementation(libs.kotlin.test)
}

compose.desktop {
    application {
        mainClass = "dev.lockermanwxlf.strata.desktop.MainKt"
        // JNA loads the core via System.load, which newer JDKs restrict unless native access is enabled.
        jvmArgs += "--enable-native-access=ALL-UNNAMED"

        nativeDistributions {
            // jpackage can only build installers for the OS it runs on; CI builds each one.
            targetFormats(TargetFormat.Msi, TargetFormat.Dmg, TargetFormat.Deb, TargetFormat.Rpm)
            packageName = "Strata"
            packageVersion = "0.1.0"
            vendor = "lockermanwxlf"
            modules("jdk.unsupported")

            windows {
                menuGroup = "Strata"
                // Fixed so MSI upgrades replace the old install. Never change it after the first release.
                upgradeUuid = "4950b7ab-f4b2-48c2-b1eb-30e4b4653dab"
            }
            macOS {
                bundleID = "dev.lockermanwxlf.strata"
            }
        }
    }
}
