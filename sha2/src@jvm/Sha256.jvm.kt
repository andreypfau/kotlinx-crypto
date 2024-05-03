package io.github.andreypfau.kotlinx.crypto

import java.security.MessageDigest

public actual class Sha256 : JvmDigest(
    MessageDigest.getInstance("SHA-256"),
    Sha256Impl.ALGORITHM_NAME
), Digest {
    actual override val blockSize: Int get() = Sha256Impl.BLOCK_SIZE_BYTES

    actual override fun update(byte: Byte): Sha256 = apply {
        super.update(byte)
    }

    actual override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha256 = apply {
        super.update(source, startIndex, endIndex)
    }
}
