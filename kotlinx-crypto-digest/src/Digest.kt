package io.github.andreypfau.kotlinx.crypto.digest

public interface Digest {
    public val digestSize: Int

    public val blockSize: Int

    public val algorithmName: String

    public fun updateByte(byte: Byte) {
        update(byteArrayOf(byte))
    }

    public fun update(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size)

    public fun digest(): ByteArray = ByteArray(digestSize).apply {
        digest(this)
    }

    public fun digest(destination: ByteArray, destinationOffset: Int = 0)

    public fun reset()
}

public inline operator fun Digest.plusAssign(byteArray: ByteArray): Unit = update(byteArray)
