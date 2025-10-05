package io.github.andreypfau.kotlinx.crypto

import kotlinx.io.Buffer
import kotlinx.io.RawSink
import kotlinx.io.UnsafeIoApi
import kotlinx.io.unsafe.UnsafeBufferOperations
import kotlinx.io.unsafe.withData

public interface Digest : RawSink {
    public val digestSize: Int

    public val blockSize: Int

    public val algorithmName: String

    public fun update(byte: Byte): Digest

    public fun update(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size): Digest

    @OptIn(UnsafeIoApi::class)
    override fun write(source: Buffer, byteCount: Long) {
        require(byteCount >= 0) { "byteCount < 0: $byteCount" }

        var remaining = byteCount

        UnsafeBufferOperations.forEachSegment(source) { context, segment ->
            if (remaining <= 0) return@forEachSegment

            context.withData(segment) { data, start, end ->
                val available = (end - start).toLong()
                val toRead = minOf(remaining, available).toInt()

                update(data, start, toRead)

                remaining -= toRead
                source.skip(toRead.toLong())
            }
        }

        if (remaining > 0) {
            throw kotlinx.io.EOFException("Not enough bytes in source buffer (missing $remaining bytes)")
        }
    }

    public fun digest(): ByteArray

    public fun digest(destination: ByteArray, destinationOffset: Int = 0)

    public fun digest(sink: RawSink) {
        val result = digest()
        val buffer = Buffer()
        buffer.write(result)
        sink.write(buffer, result.size.toLong())
    }

    public fun reset()

    override fun close() {
        reset()
    }

    override fun flush() {
    }
}

public inline operator fun Digest.plusAssign(byteArray: ByteArray) {
    update(byteArray)
}
