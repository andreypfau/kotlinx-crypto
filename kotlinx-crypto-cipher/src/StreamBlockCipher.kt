package io.github.andreypfau.kotlinx.crypto.cipher

import kotlinx.io.Buffer
import kotlinx.io.RawSink
import kotlinx.io.RawSource
import kotlin.math.min

public abstract class StreamBlockCipher(
    public val cipher: BlockCipher
) : DefaultMultiBlockCipher(), StreamCipher {

    override fun returnByte(input: Byte): Byte = calculateByte(input)

    protected abstract fun calculateByte(byte: Byte): Byte

    override fun processBytes(source: RawSource, destination: RawSink, byteCount: Long): Long {
        var remaining = byteCount
        val srcBuffer = Buffer()
        val dstBuffer = Buffer()
        while (remaining > 0) {
            val read = source.readAtMostTo(srcBuffer, min(remaining, 4096))
            if (read == 0L) {
                break
            }
            while (!srcBuffer.exhausted()) {
                dstBuffer.writeByte(calculateByte(srcBuffer.readByte()))
            }
            destination.write(dstBuffer, dstBuffer.size)
            remaining -= read
        }
        return byteCount - remaining
    }

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
