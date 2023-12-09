package io.github.andreypfau.kotlinx.crypto.cipher

public abstract class StreamBlockCipher(
    public val cipher: BlockCipher
) : DefaultMultiBlockCipher(), StreamCipher {

    override fun returnByte(input: Byte): Byte = calculateByte(input)

    protected abstract fun calculateByte(byte: Byte): Byte

    override fun processBytes(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int
    ): Int {
        require(endIndex <= source.size) {
            "source too small"
        }
        require(destinationOffset + (endIndex - startIndex) <= destination.size) {
            "destination too small"
        }

        var srcStart = startIndex
        var dstStart = destinationOffset
        while (srcStart < endIndex) {
            destination[dstStart++] = calculateByte(source[srcStart++])
        }
        return endIndex - startIndex
    }
}
