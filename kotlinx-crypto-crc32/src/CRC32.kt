package io.github.andreypfau.kotlinx.crypto.crc32

import io.github.andreypfau.kotlinx.crypto.digest.IntDigest
import io.github.andreypfau.kotlinx.crypto.digest.plusAssign
import kotlin.experimental.xor

public expect class CRC32 public constructor() : IntDigest

public fun crc32(bytes: ByteArray): Int {
    val crc32 = CRC32Impl()
    crc32 += bytes
    return crc32.intDigest()
}

public open class CRC32Impl internal constructor(
    private val table: UIntArray
): IntDigest {
    public constructor() : this(IEEE_TABLE)

    override val algorithmName: String get() = ALGORITHM_NAME

    private var crc32: UInt = 0xffffffffU

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        for (i in startIndex until endIndex) {
            val index = source[i].xor(crc32.toByte()).toUByte()
            crc32 = table[index.toInt()].xor(crc32.shr(8))
        }
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        val intDigest = intDigest()
        destination[destinationOffset] = (intDigest shr 24 and 0xFF).toByte()
        destination[destinationOffset + 1] = (intDigest shr 16 and 0xFF).toByte()
        destination[destinationOffset + 2] = (intDigest shr 8 and 0xFF).toByte()
        destination[destinationOffset + 3] = (intDigest and 0xFF).toByte()
    }

    override fun reset() {
        crc32 = 0xffffffffU
    }

    override fun intDigest(): Int = crc32.xor(0xffffffffU).toInt()

    public companion object {
        public const val ALGORITHM_NAME: String = "CRC-32"
    }
}
