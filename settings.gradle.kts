pluginManagement {
    includeBuild("build-logic")

    repositories {
        mavenCentral()
        google()
        gradlePluginPortal()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.5.0"
}

rootProject.name = "kotlinx-crypto"

include(":kotlinx-crypto-cipher")
include(":kotlinx-crypto-digest")
include(":kotlinx-crypto-sha1")
include(":kotlinx-crypto-sha2")
include(":kotlinx-crypto-keccak")
include(":kotlinx-crypto-md")
include(":kotlinx-crypto-aes")
include(":kotlinx-crypto-crc32")
include(":kotlinx-crypto-blake2")
include(":kotlinx-crypto-hmac")
include(":kotlinx-crypto-pbkdf2")
include(":kotlinx-crypto-benchmarks")
project(":kotlinx-crypto-benchmarks").projectDir = file("./benchmarks")

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            version("java", "8")
            version("jmh", "1.36")
            version("benchmark", "0.4.10")
            version("kotlin", "1.9.20")

            library("kotlin-gradle-plugin", "org.jetbrains.kotlin", "kotlin-gradle-plugin").versionRef("kotlin")
            library("kotlinx-benchmark-runtime", "org.jetbrains.kotlinx", "kotlinx-benchmark-runtime").versionRef("benchmark")
        }
    }
}
