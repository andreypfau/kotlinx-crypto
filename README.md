# Kotlin/Multiplatform Crypto

[![Maven Central](https://img.shields.io/maven-central/v/io.github.andreypfau/kotlinx-crypto-digest.svg)](https://search.maven.org/artifact/io.github.andreypfau/kotlinx-crypto-digest)
[![License](https://img.shields.io/github/license/andreypfau/kotlinx-crypto?color=blue)](https://github.com/andreypfau/kotlinx-crypto/blob/main/LICENSE)
[![Kotlin](https://img.shields.io/badge/kotlin-2.0.0-blue.svg?logo=kotlin)](http://kotlinlang.org)

**A multiplatform Kotlin library providing basic cryptographic functions and primitives**

### Gradle Kotlin DSL:

```kotlin
repositories {
    mavenCentral()
}

val kotlinxCryptoVersion = "0.0.4"

dependencies {
    implementation("io.github.andreypfau:kotlinx-crypto-aes:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-blake2:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-crc32:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-hmac:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-keccak:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-pbkdf2:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-poly1305:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-salsa20:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-sha1:$kotlinxCryptoVersion") 
    implementation("io.github.andreypfau:kotlinx-crypto-sha2:$kotlinxCryptoVersion") 
}
```
