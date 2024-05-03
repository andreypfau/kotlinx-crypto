# Kotlin/Multiplatform Crypto: SHA-1

Pure Kotlin implementation of the [SHA-1](https://en.wikipedia.org/wiki/SHA-1) cryptographic hash algorithm.

> [!CAUTION]
> The SHA-1 hash function should be considered cryptographically broken and unsuitable for
> further use in any security critical capacity, as it
> is [practically vulnerable to chosen-prefix collisions](https://sha-mbles.github.io/)

## Example

```kotlin
import io.github.andreypfau.kotlinx.crypto.sha1

val result = sha1("hello world".encodeToByteArray())
assertContentEquals(result, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed".hexToByteArray())
```
