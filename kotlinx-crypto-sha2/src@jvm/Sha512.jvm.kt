package io.github.andreypfau.kotlinx.crypto

import java.security.MessageDigest

public actual class Sha512 : JvmDigest(
    MessageDigest.getInstance("SHA-512"),
    Sha512Impl.ALGORITHM_NAME
), Digest {
    override val blockSize: Int get() = Sha512Impl.BLOCK_SIZE_BYTES

    override fun update(byte: Byte): Sha512 = apply {
        super.update(byte)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha512 = apply {
        super.update(source, startIndex, endIndex)
    }
}
