package io.github.andreypfau.kotlinx.crypto.digest

import java.security.MessageDigest

public abstract class JvmDigest(
    private val digest: MessageDigest,
    override val algorithmName: String
) : Digest {
    override val digestSize: Int
        get() = digest.digestLength

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        digest.update(source, startIndex, endIndex)
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        digest.digest(destination, destinationOffset, digest.digestLength)
    }

    override fun reset() {
        digest.reset()
    }
}
