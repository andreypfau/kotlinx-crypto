plugins {
    id("publish")
}

kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":kotlinx-crypto-cipher"))
            }
        }
        val commonTest by getting {
            dependencies {
                api(project(":kotlinx-crypto-poly1305"))
            }
        }
    }
}
