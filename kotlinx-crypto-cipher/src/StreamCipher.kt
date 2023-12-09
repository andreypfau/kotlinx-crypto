package io.github.andreypfau.kotlinx.crypto.cipher

public interface StreamCipher {
    public val algorithmName: String

    public fun returnByte(input: Byte): Byte

    public fun processBytes(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int = 0,
        startIndex: Int = 0,
        endIndex: Int = source.size
    ): Int

    public fun reset()
}
