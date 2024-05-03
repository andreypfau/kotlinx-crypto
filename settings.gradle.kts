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

fun module(name: String) {
    include(":kotlinx-crypto-$name")
    project(":kotlinx-crypto-$name").projectDir = file("./$name")
}

module("digest")
module("cipher")
module("subtle")
module("sha1")
module("sha2")
module("keccak")
module("aes")
module("crc32")
module("blake2")
module("hmac")
module("pbkdf2")
module("salsa20")
module("poly1305")
