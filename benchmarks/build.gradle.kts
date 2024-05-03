import org.jetbrains.kotlin.gradle.dsl.ExplicitApiMode

plugins {
    id("org.jetbrains.kotlinx.benchmark") version "0.4.10"
}

kotlin {
    explicitApi = ExplicitApiMode.Disabled
    sourceSets {
        commonMain {
            dependencies {
//                implementation(project(":kotlinx-crypto-crc32"))
            }
        }
    }
}

benchmark {
    targets {
        register("jvm")
        register("macosArm64")
    }
}
