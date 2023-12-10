package io.github.andreypfau.kotlinx.crypto.crc32

import io.github.andreypfau.kotlinx.crypto.digest.IntDigest
import kotlinx.io.Buffer
import kotlinx.io.RawSink
import java.util.zip.CRC32
import kotlin.math.min

public actual class CRC32 : IntDigest {
    private val crc32jvm = CRC32()

    override fun write(source: Buffer, byteCount: Long) {
        var remaining = byteCount
        val buffer = ByteArray(15)
        while (remaining > 0) {
            val read = source.readAtMostTo(buffer, 0, min(remaining, buffer.size.toLong()).toInt())
            write(buffer, 0, read)
            remaining -= read
        }
    }

    override fun write(source: ByteArray, startIndex: Int, endIndex: Int) {
        crc32jvm.update(source, startIndex, endIndex - startIndex)
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        val intDigest = intDigest()
        destination[destinationOffset] = (intDigest shr 24 and 0xFF).toByte()
        destination[destinationOffset + 1] = (intDigest shr 16 and 0xFF).toByte()
        destination[destinationOffset + 2] = (intDigest shr 8 and 0xFF).toByte()
        destination[destinationOffset + 3] = (intDigest and 0xFF).toByte()
    }

    override fun digest(sink: RawSink) {
        val intDigest = intDigest()
        val buffer = Buffer()
        buffer.writeInt(intDigest)
        sink.write(buffer, digestSize.toLong())
    }

    override fun reset() {
        crc32jvm.reset()
    }

    override fun intDigest(): Int = crc32jvm.value.toInt()
}
