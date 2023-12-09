kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":kotlinx-crypto-digest"))
                api(project(":kotlinx-crypto-md"))
            }
        }
    }
}
