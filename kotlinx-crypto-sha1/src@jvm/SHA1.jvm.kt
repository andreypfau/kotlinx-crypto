package io.github.andreypfau.kotlinx.crypto.sha1

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.digest.JvmDigest
import java.security.MessageDigest

public actual class SHA1 : JvmDigest(
    MessageDigest.getInstance("SHA-1"),
    SHA1Impl.ALGORITHM_NAME
), Digest {
    override val blockSize: Int get() = SHA1Impl.BLOCK_SIZE_BYTES
}
