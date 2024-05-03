package io.github.andreypfau.kotlinx.crypto

import java.security.MessageDigest

public actual class Sha1 : JvmDigest(
    MessageDigest.getInstance("SHA-1"),
    Sha1Impl.ALGORITHM_NAME
), Digest {
    actual override val blockSize: Int get() = Sha1Impl.BLOCK_SIZE_BYTES

    actual override fun update(byte: Byte): Sha1 = apply {
        super.update(byte)
    }

    actual override fun update(
        source: ByteArray,
        startIndex: Int,
        endIndex: Int
    ): Sha1 = apply {
        super.update(source, startIndex, endIndex)
    }
}
