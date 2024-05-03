package io.github.andreypfau.kotlinx.crypto

public interface IntDigest : Digest {
    override val digestSize: Int
        get() = Int.SIZE_BYTES

    override val blockSize: Int
        get() = 1

    override val algorithmName: String

    public fun intDigest(): Int

    override fun update(byte: Byte): IntDigest

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): IntDigest

    override fun digest(): ByteArray

    override fun digest(destination: ByteArray, destinationOffset: Int)

    override fun reset()
}
