package io.github.andreypfau.kotlinx.crypto.sha2

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.digest.JvmDigest
import java.security.MessageDigest

public actual class SHA512 : JvmDigest(
    MessageDigest.getInstance("SHA-512"),
    SHA512Impl.ALGORITHM_NAME
), Digest {
    override val blockSize: Int get() = SHA512Impl.BLOCK_SIZE_BYTES
}
