package io.github.andreypfau.kotlinx.crypto

public class Sha1Impl : GeneralDigest(), Digest {
    private val x = IntArray(80)
    private var xOff = 0
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0
    private var h5 = 0

    override val digestSize: Int
        get() = DIGEST_SIZE_BYTES
    override val blockSize: Int
        get() = BLOCK_SIZE_BYTES
    override val algorithmName: String
        get() = ALGORITHM_NAME

    init {
        reset()
    }

    override fun update(byte: Byte): Sha1Impl = apply {
        super.update(byte)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha1Impl = apply {
        super.update(source, startIndex, endIndex)
    }

    override fun processWord(input: ByteArray, offset: Int) {
        x[xOff] = input.getIntAt(offset)
        if (++xOff == 16) {
            processBlock()
        }
    }

    override fun processLength(bitLength: Long) {
        if (xOff > 14) {
            processBlock()
        }
        x[14] = (bitLength.ushr(32)).toInt()
        x[15] = bitLength.toInt()
    }

    override fun digest(): ByteArray {
        val result = ByteArray(DIGEST_SIZE_BYTES)
        digest(result)
        return result
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        finish()
        destination.setIntAt(destinationOffset, h1)
        destination.setIntAt(destinationOffset + 4, h2)
        destination.setIntAt(destinationOffset + 8, h3)
        destination.setIntAt(destinationOffset + 12, h4)
        destination.setIntAt(destinationOffset + 16, h5)
        reset()
    }

    override fun reset() {
        super.reset()
        h1 = 0x67452301
        h2 = 0xefcdab89.toInt()
        h3 = 0x98badcfe.toInt()
        h4 = 0x10325476
        h5 = 0xc3d2e1f0.toInt()
        xOff = 0
        x.fill(0)
    }

    override fun processBlock() {
        // expand 16 word block into 80 word block.
        for (i in 16..79) {
            val t = x[i - 3] xor x[i - 8] xor x[i - 14] xor x[i - 16]
            x[i] = t shl 1 or (t ushr 31)
        }

        // set up working variables.
        var a = h1
        var b = h2
        var c = h3
        var d = h4
        var e = h5
        var idx = 0
        var f: Int
        var h: Int
        var g: Int

        // round 1
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            f = (b and c) or (b.inv() and d)
            e += (a shl 5 or (a ushr 27)) + f + x[idx++] + Y1
            b = b shl 30 or (b ushr 2)

            f = (a and b) or (a.inv() and c)
            d += (e shl 5 or (e ushr 27)) + f + x[idx++] + Y1
            a = a shl 30 or (a ushr 2)

            f = (e and a) or (e.inv() and b)
            c += (d shl 5 or (d ushr 27)) + f + x[idx++] + Y1
            e = e shl 30 or (e ushr 2)

            f = (d and e) or (d.inv() and a)
            b += (c shl 5 or (c ushr 27)) + f + x[idx++] + Y1
            d = d shl 30 or (d ushr 2)

            f = (c and d) or (c.inv() and e)
            a += (b shl 5 or (b ushr 27)) + f + x[idx++] + Y1
            c = c shl 30 or (c ushr 2)
        }

        // round 2
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            h = (b xor c xor d)
            e += (a shl 5 or (a ushr 27)) + h + x[idx++] + Y2
            b = b shl 30 or (b ushr 2)

            h = (a xor b xor c)
            d += (e shl 5 or (e ushr 27)) + h + x[idx++] + Y2
            a = a shl 30 or (a ushr 2)

            h = (e xor a xor b)
            c += (d shl 5 or (d ushr 27)) + h + x[idx++] + Y2
            e = e shl 30 or (e ushr 2)

            h = (d xor e xor a)
            b += (c shl 5 or (c ushr 27)) + h + x[idx++] + Y2
            d = d shl 30 or (d ushr 2)

            h = (c xor d xor e)
            a += (b shl 5 or (b ushr 27)) + h + x[idx++] + Y2
            c = c shl 30 or (c ushr 2)
        }

        // round 3
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            g = (b and c) or (b and d) or (c and d)
            e += (a shl 5 or (a ushr 27)) + g + x[idx++] + Y3
            b = b shl 30 or (b ushr 2)

            g = (a and b) or (a and c) or (b and c)
            d += (e shl 5 or (e ushr 27)) + g + x[idx++] + Y3
            a = a shl 30 or (a ushr 2)

            g = (e and a) or (e and b) or (a and b)
            c += (d shl 5 or (d ushr 27)) + g + x[idx++] + Y3
            e = e shl 30 or (e ushr 2)

            g = (d and e) or (d and a) or (e and a)
            b += (c shl 5 or (c ushr 27)) + g + x[idx++] + Y3
            d = d shl 30 or (d ushr 2)

            g = (c and d) or (c and e) or (d and e)
            a += (b shl 5 or (b ushr 27)) + g + x[idx++] + Y3
            c = c shl 30 or (c ushr 2)
        }

        // round 4
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            h = (b xor c xor d)
            e += (a shl 5 or (a ushr 27)) + h + x[idx++] + Y4
            b = b shl 30 or (b ushr 2)

            h = (a xor b xor c)
            d += (e shl 5 or (e ushr 27)) + h + x[idx++] + Y4
            a = a shl 30 or (a ushr 2)

            h = (e xor a xor b)
            c += (d shl 5 or (d ushr 27)) + h + x[idx++] + Y4
            e = e shl 30 or (e ushr 2)

            h = (d xor e xor a)
            b += (c shl 5 or (c ushr 27)) + h + x[idx++] + Y4
            d = d shl 30 or (d ushr 2)

            h = (c xor d xor e)
            a += (b shl 5 or (b ushr 27)) + h + x[idx++] + Y4
            c = c shl 30 or (c ushr 2)
        }

        h1 += a
        h2 += b
        h3 += c
        h4 += d
        h5 += e

        xOff = 0
        x.fill(0, 0, 16)
    }

    public companion object {
        public const val ALGORITHM_NAME: String = "SHA-1"
        public const val DIGEST_SIZE_BYTES: Int = 20
        public const val BLOCK_SIZE_BYTES: Int = 64

        private const val Y1 = 0x5a827999
        private const val Y2 = 0x6ed9eba1
        private const val Y3 = -0x70e44324
        private const val Y4 = -0x359d3e2a

        private fun ByteArray.setIntAt(index: Int, value: Int) {
            this[index] = (value ushr 24).toByte()
            this[index + 1] = (value ushr 16).toByte()
            this[index + 2] = (value ushr 8).toByte()
            this[index + 3] = value.toByte()
        }

        private fun ByteArray.getIntAt(index: Int): Int {
            return (this[index].toInt() and 0xff shl 24
                    or (this[index + 1].toInt() and 0xff shl 16)
                    or (this[index + 2].toInt() and 0xff shl 8)
                    or (this[index + 3].toInt() and 0xff))
        }
    }
}
