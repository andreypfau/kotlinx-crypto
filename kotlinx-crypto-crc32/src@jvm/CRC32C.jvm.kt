package io.github.andreypfau.kotlinx.crypto.crc32

import io.github.andreypfau.kotlinx.crypto.digest.IntDigest

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
        { CRC32Impl(CASTAGNOLI_TABLE) }
    }
}

internal class CRC32CJvm : IntDigest {
    private val jvmCrc32c = java.util.zip.CRC32C()

    override val algorithmName: String get() = "CRC-32C"

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        jvmCrc32c.update(source, startIndex, endIndex - startIndex)
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        val intDigest = intDigest()
        destination[destinationOffset] = (intDigest shr 24 and 0xFF).toByte()
        destination[destinationOffset + 1] = (intDigest shr 16 and 0xFF).toByte()
        destination[destinationOffset + 2] = (intDigest shr 8 and 0xFF).toByte()
        destination[destinationOffset + 3] = (intDigest and 0xFF).toByte()
    }

    override fun intDigest(): Int = jvmCrc32c.value.toInt()

    override fun reset() {
        jvmCrc32c.reset()
    }
}
