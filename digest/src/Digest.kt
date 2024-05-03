package io.github.andreypfau.kotlinx.crypto

public interface Digest {
    public val digestSize: Int

    public val blockSize: Int

    public val algorithmName: String

    public fun update(byte: Byte): Digest

    public fun update(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size): Digest

    public fun digest(): ByteArray

    public fun digest(destination: ByteArray, destinationOffset: Int = 0)

    public fun reset()
}

public inline operator fun Digest.plusAssign(byteArray: ByteArray): Unit {
    update(byteArray)
}
