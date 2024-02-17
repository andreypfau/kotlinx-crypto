package io.github.andreypfau.kotlinx.crypto.sha2

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.digest.JvmDigest
import java.security.MessageDigest

public actual class SHA256 : JvmDigest(
    MessageDigest.getInstance("SHA-256"),
    SHA256Impl.ALGORITHM_NAME
), Digest {
    override val blockSize: Int get() = SHA256Impl.BLOCK_SIZE_BYTES
}
