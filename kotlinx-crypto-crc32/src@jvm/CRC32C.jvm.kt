package io.github.andreypfau.kotlinx.crypto.crc32

import io.github.andreypfau.kotlinx.crypto.digest.IntDigest
import kotlinx.io.Buffer
import kotlinx.io.RawSink
import kotlin.math.min

public actual class CRC32C private constructor(
    private val delegated: IntDigest
): IntDigest by delegated {
    public actual constructor() : this(crc32Delegate())
}

private val crc32Delegate by lazy(LazyThreadSafetyMode.PUBLICATION) {
    val hasCrc32c = try {
        Class.forName("java.util.zip.CRC32C")
        true
    } catch (e: ClassNotFoundException) {
        false
    }

    if (hasCrc32c) {
        { CRC32CJvm() }
    } else {
        { CRC32Pure(CASTAGNOLI_TABLE) }
    }
}

internal class CRC32CJvm : IntDigest {
    private val jvmCrc32c = java.util.zip.CRC32C()

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
        jvmCrc32c.update(source, startIndex, endIndex - startIndex)
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

    override fun intDigest(): Int = jvmCrc32c.value.toInt()

    override fun reset() {
        jvmCrc32c.reset()
    }
}
