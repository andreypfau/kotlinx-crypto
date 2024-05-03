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
    }
}
