package io.github.andreypfau.kotlinx.crypto.crc32

import io.github.andreypfau.kotlinx.crypto.digest.IntDigest
import io.github.andreypfau.kotlinx.crypto.digest.plusAssign
import kotlinx.io.Buffer
import kotlinx.io.RawSink
import kotlin.experimental.xor

public expect class CRC32 public constructor() : IntDigest

public fun crc32(bytes: ByteArray): Int {
    val crc32 = CRC32Pure()
    crc32 += bytes
    return crc32.intDigest()
}

public open class CRC32Pure internal constructor(
    private val table: UIntArray
): IntDigest {
    public constructor() : this(IEEE_TABLE)

    private var crc32: UInt = 0xffffffffU

    override fun write(source: Buffer, byteCount: Long) {
        val tempBuffer = Buffer()
        source.copyTo(tempBuffer, 0, byteCount)
        while (!tempBuffer.exhausted()) {
            update(tempBuffer.readByte())
        }
    }

    override fun write(source: ByteArray, startIndex: Int, endIndex: Int) {
        for (i in startIndex until endIndex) {
            update(source[i])
        }
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
        if (sink is Buffer) {
            sink.writeInt(intDigest)
        } else {
            val buffer = Buffer()
            buffer.writeInt(intDigest)
            sink.write(buffer, digestSize.toLong())
        }
    }

    private inline fun update(value: Byte) {
        val index = value.xor(crc32.toByte()).toUByte()
        crc32 = table[index.toInt()].xor(crc32.shr(8))
    }

    override fun reset() {
        crc32 = 0xffffffffU
    }

    override fun intDigest(): Int = crc32.xor(0xffffffffU).toInt()
}
