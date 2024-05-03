package io.github.andreypfau.kotlinx.crypto

public expect class CRC32C public constructor() : IntDigest {
    override val digestSize: Int
    override val blockSize: Int
    override val algorithmName: String

    override fun intDigest(): Int

    override fun update(byte: Byte): CRC32C

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): CRC32C

    override fun digest(): ByteArray

    override fun digest(destination: ByteArray, destinationOffset: Int)

    override fun reset()
}

public fun crc32c(bytes: ByteArray): Int {
    val crc32c = CRC32C()
    crc32c += bytes
    return crc32c.intDigest()
}

public class CRC32CImpl : CRC32Impl(CASTAGNOLI_TABLE), IntDigest {
    override fun update(byte: Byte): CRC32CImpl = apply {
        super.update(byte)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): CRC32CImpl = apply {
        super.update(source, startIndex, endIndex)
    }
}
