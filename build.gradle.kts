plugins {
    kotlin("multiplatform") version "1.9.20"
}

allprojects {
    group = "io.github.andreypfau"
    version = "1.0-SNAPSHOT"

    apply(plugin = "kotlin-multiplatform")

    repositories {
        mavenCentral()
    }

    kotlin {

        explicitApi()

        jvm()

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

            if (project.name != "a") {
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
}
