# Kotlin/Multiplatform Crypto: SHA-2

Pure Kotlin implementation of the [SHA-2](https://en.wikipedia.org/wiki/SHA-2) cryptographic hash algorithms.

There are 2 standard algorithms in the SHA-2 family:
`Sha256`, `Sha512`

## Example

```kotlin
import io.github.andreypfau.kotlinx.crypto.sha256

val result = sha256("hello world".encodeToByteArray())
assertContentEquals(result, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".hexToByteArray())
```
