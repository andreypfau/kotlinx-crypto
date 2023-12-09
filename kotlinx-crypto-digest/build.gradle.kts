kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies {
                api("org.jetbrains.kotlinx:kotlinx-io-core:0.3.0")
            }
        }
    }
}
