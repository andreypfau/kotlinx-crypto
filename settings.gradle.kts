plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.5.0"
}
rootProject.name = "kotlinx-crypto"

include(":kotlinx-crypto-cipher")
include(":kotlinx-crypto-digest")
include(":kotlinx-crypto-sha2")
include(":kotlinx-crypto-md")
include(":kotlinx-crypto-aes")
