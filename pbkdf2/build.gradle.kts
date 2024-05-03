plugins {
    id("publish")
}

kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":kotlinx-crypto-hmac"))
            }
        }
        val commonTest by getting {
            dependencies {
                api(project(":kotlinx-crypto-sha1"))
                api(project(":kotlinx-crypto-sha2"))
            }
        }
    }
}
