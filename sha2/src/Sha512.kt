package io.github.andreypfau.kotlinx.crypto

public expect class Sha512 public constructor() : Digest {
    public override val digestSize: Int

    public override val blockSize: Int

    public override val algorithmName: String

    public override fun update(byte: Byte): Sha512

    public override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha512

    public override fun digest(): ByteArray

    public override fun digest(destination: ByteArray, destinationOffset: Int)

    public override fun reset()
}

public fun sha512(data: ByteArray): ByteArray {
    val sha512 = Sha512()
    sha512 += data
    return sha512.digest()
}

/**
 * FIPS 180-2 implementation of SHA-512.
 *
 * ```
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 */
public class Sha512Impl : LongDigest(), Digest {
    init {
        reset()
    }

    override val digestSize: Int get() = SIZE_BYTES

    override val blockSize: Int get() = BLOCK_SIZE_BYTES

    override val algorithmName: String get() = ALGORITHM_NAME

    override fun update(byte: Byte): Sha512Impl = apply {
        super.update(byte)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha512Impl = apply {
        super.update(source, startIndex, endIndex)
    }

    override fun digest(): ByteArray {
        val result = ByteArray(SIZE_BYTES)
        digest(result)
        return result
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        finish()
        destination.setLongAt(destinationOffset, h1)
        destination.setLongAt(destinationOffset + 8, h2)
        destination.setLongAt(destinationOffset + 16, h3)
        destination.setLongAt(destinationOffset + 24, h4)
        destination.setLongAt(destinationOffset + 32, h5)
        destination.setLongAt(destinationOffset + 40, h6)
        destination.setLongAt(destinationOffset + 48, h7)
        destination.setLongAt(destinationOffset + 56, h8)
        reset()
    }

    override fun reset() {
        super.reset()

        /*
        SHA-512 initial hash value
        The first 64 bits of the fractional parts of the square roots
        of the first eight prime numbers
        */
        h1 = 0x6a09e667f3bcc908L
        h2 = 0xbb67ae8584caa73buL.toLong()
        h3 = 0x3c6ef372fe94f82bL
        h4 = 0xa54ff53a5f1d36f1uL.toLong()
        h5 = 0x510e527fade682d1L
        h6 = 0x9b05688c2b3e6c1fuL.toLong()
        h7 = 0x1f83d9abfb41bd6bL
        h8 = 0x5be0cd19137e2179L
    }

    public companion object {
        public const val ALGORITHM_NAME: String = "SHA-512"
        public const val SIZE_BYTES: Int = 64
        public const val SIZE_BITS: Int = SIZE_BYTES * Byte.SIZE_BITS
        public const val BLOCK_SIZE_BYTES: Int = 128
        public const val BLOCK_SIZE_BITS: Int = BLOCK_SIZE_BYTES * Byte.SIZE_BITS

        private fun ByteArray.setLongAt(index: Int, value: Long) {
            this[index] = (value ushr 56).toByte()
            this[index + 1] = (value ushr 48).toByte()
            this[index + 2] = (value ushr 40).toByte()
            this[index + 3] = (value ushr 32).toByte()
            this[index + 4] = (value ushr 24).toByte()
            this[index + 5] = (value ushr 16).toByte()
            this[index + 6] = (value ushr 8).toByte()
            this[index + 7] = value.toByte()
        }
    }
}
