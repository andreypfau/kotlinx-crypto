import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("multiplatform") version "2.0.0-RC2"
    id("publish") apply false
}

allprojects {
    group = "io.github.andreypfau"
    version = "0.0.4"

    apply(plugin = "kotlin-multiplatform")

    repositories {
        mavenCentral()
    }

    tasks.withType<KotlinCompile>().configureEach {
        compilerOptions {
            freeCompilerArgs.add("-Xexpect-actual-classes")
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
        }
    }

    kotlin {
        explicitApi()

        jvm()

        iosArm64()
        iosSimulatorArm64()
        iosX64()

        macosArm64()
        macosX64()

        tvosArm64()
        tvosSimulatorArm64()
        tvosX64()

        watchosArm32()
        watchosArm64()
        watchosDeviceArm64()
        watchosSimulatorArm64()
        watchosX64()

        mingwX64()

        linuxArm64()
        linuxX64()

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
