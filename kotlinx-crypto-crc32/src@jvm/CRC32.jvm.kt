package io.github.andreypfau.kotlinx.crypto


public actual class CRC32 : IntDigest {
    private val crc32jvm = java.util.zip.CRC32()

    override val algorithmName: String get() = "CRC-32"

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): CRC32 = apply {
        crc32jvm.update(source, startIndex, endIndex - startIndex)
    }

    override fun update(byte: Byte): CRC32 = apply {
        crc32jvm.update(byte.toInt())
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        val intDigest = intDigest()
        destination[destinationOffset] = (intDigest shr 24 and 0xFF).toByte()
        destination[destinationOffset + 1] = (intDigest shr 16 and 0xFF).toByte()
        destination[destinationOffset + 2] = (intDigest shr 8 and 0xFF).toByte()
        destination[destinationOffset + 3] = (intDigest and 0xFF).toByte()
    }

    override fun reset() {
        crc32jvm.reset()
    }

    override fun intDigest(): Int = crc32jvm.value.toInt()
}
