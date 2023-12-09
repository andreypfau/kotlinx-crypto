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
        macosArm64()
        macosX64()

        linuxX64()
        linuxArm64()

        mingwX64()

//        sourceSets {
//            main {
//                kotlin.srcDir("src")
//                resources.srcDir("resources")
//            }
//        }

        sourceSets {
            all {
                languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
                languageSettings.optIn("kotlin.ExperimentalStdlibApi")
            }

            val commonMain by getting {
                kotlin.srcDir("src")
            }
            val jvmMain by getting {
                kotlin.srcDir("src@jvm")
            }
            val appleMain by creating {
                kotlin.srcDir("src@apple")
                dependsOn(commonMain)
                getByName("iosArm64Main").dependsOn(this)
                getByName("iosX64Main").dependsOn(this)
                getByName("iosSimulatorArm64Main").dependsOn(this)
                getByName("macosArm64Main").dependsOn(this)
                getByName("macosX64Main").dependsOn(this)
            }

            val linuxMain by creating {
                kotlin.srcDir("src@linux")
                dependsOn(commonMain)
                getByName("linuxX64Main").dependsOn(this)
                getByName("linuxArm64Main").dependsOn(this)
            }

            val mingwX64Main by getting {
                kotlin.srcDir("src@mingw")
            }

            val commonTest by getting {
                kotlin.srcDir("test")
                dependencies {
                    implementation(kotlin("test"))
                }
            }
        }
    }
}
