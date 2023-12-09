package io.github.andreypfau.kotlinx.crypto.sha2

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.digest.plusAssign
import kotlinx.io.Buffer
import kotlinx.io.RawSink
import kotlinx.io.readTo

public expect class SHA512 public constructor(): Digest

public fun sha512(data: ByteArray): ByteArray {
    val sha512 = SHA512()
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
public class SHA512Impl : LongDigest(), Digest {
    init {
        reset()
    }

    override val digestSize: Int get() = SIZE_BYTES

    override fun digest(sink: RawSink) {
        if (sink is Buffer) {
            digest(sink)
        } else {
            val buffer = Buffer()
            digest(buffer)
            sink.write(buffer, digestSize.toLong())
        }
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        val buffer = Buffer()
        digest(buffer)
        buffer.readTo(destination, destinationOffset, destinationOffset + digestSize)
    }

    private fun digest(buffer: Buffer) {
        finish()
        buffer.apply {
            writeLong(h1)
            writeLong(h2)
            writeLong(h3)
            writeLong(h4)
            writeLong(h5)
            writeLong(h6)
            writeLong(h7)
            writeLong(h8)
        }
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
    }
}
