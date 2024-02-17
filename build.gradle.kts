plugins {
    kotlin("multiplatform") version "1.9.22"
    id("publish") apply false
}

allprojects {
    group = "io.github.andreypfau"
    version = "0.0.2"

    apply(plugin = "kotlin-multiplatform")

    repositories {
        mavenCentral()
    }

    kotlin {

        explicitApi()

        jvm {
            compilations.all {
                kotlinOptions {
                    jvmTarget = "1.8"
                }
            }
        }

        iosX64()
        iosArm64()
        iosSimulatorArm64()

        macosX64()
        macosArm64()

        tvosX64()
        tvosArm64()
        tvosSimulatorArm64()

        watchosX64()
        watchosArm32()
        watchosArm64()
        watchosSimulatorArm64()
        watchosDeviceArm64()

        mingwX64()

        linuxX64()
        linuxArm64()

        js(IR) {
            nodejs()
            browser()
        }

        @OptIn(org.jetbrains.kotlin.gradle.targets.js.dsl.ExperimentalWasmDsl::class)
        wasmJs {
            nodejs()
            browser()
            binaries.executable()
        }

        sourceSets {
            all {
                languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
                languageSettings.optIn("kotlin.ExperimentalStdlibApi")
            }

            val commonTest by getting {
                dependencies {
                    implementation(kotlin("test"))
                }
            }

            all {
                if (name.endsWith("Main")) {
                    kotlin.srcDir("src${if (name.startsWith("common")) "" else "@${name.removeSuffix("Main")}"}")
                }
                if (name.endsWith("Test")) {
                    kotlin.srcDir("test${if (name.startsWith("common")) "" else "@${name.removeSuffix("Test")}"}")
                }
            }
        }
    }
}
