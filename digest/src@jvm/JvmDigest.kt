package io.github.andreypfau.kotlinx.crypto

import java.security.MessageDigest

public abstract class JvmDigest(
    protected val digest: MessageDigest,
    override val algorithmName: String
) : Digest {
    override val digestSize: Int
        get() = digest.digestLength

    override fun update(byte: Byte): JvmDigest = apply {
        digest.update(byte)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): JvmDigest = apply {
        digest.update(source, startIndex, endIndex)
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        digest.digest(destination, destinationOffset, digest.digestLength)
    }

    override fun digest(): ByteArray {
        val result = ByteArray(digestSize)
        digest(result)
        return result
    }

    override fun reset() {
        digest.reset()
    }
}
