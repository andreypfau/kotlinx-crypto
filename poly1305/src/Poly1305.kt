package io.github.andreypfau.kotlinx.crypto

import kotlin.math.min

public inline fun poly1305(
    destination: ByteArray,
    destinationOffset: Int = 0,
    message: ByteArray,
    startIndex: Int = 0,
    endIndex: Int = message.size,
    key: ByteArray
) {
    val poly = Poly1305(key)
    poly.update(message, startIndex, endIndex)
    poly.digest(destination, destinationOffset)
}

public inline fun poly1305(
    message: ByteArray,
    key: ByteArray
): ByteArray {
    val poly = Poly1305(key)
    poly.update(message)
    return poly.digest()
}

public class Poly1305(
    key: ByteArray
) : Mac {
    private val r = uintArrayOf(
        key.getUIntLe(0) and 0x3FF_FFFFu,
        (key.getUIntLe(3) shr 2) and 0x3FF_FF03u,
        (key.getUIntLe(6) shr 4) and 0x3FF_C0FFu,
        (key.getUIntLe(9) shr 6) and 0x3F0_3FFFu,
        (key.getUIntLe(12) shr 8) and 0x00F_FFFFu
    )

    private val pad = uintArrayOf(
        key.getUIntLe(16),
        key.getUIntLe(20),
        key.getUIntLe(24),
        key.getUIntLe(28)
    )

    private val h = uintArrayOf(0u, 0u, 0u, 0u, 0u)

    private val block = ByteArray(BLOCK_SIZE_BYTES)
    private var blockOffset = 0
    private val singleByte = ByteArray(1)

    override val algorithmName: String
        get() = "Poly1305"
    override val macSize: Int
        get() = BLOCK_SIZE_BYTES
    override val blockSize: Int
        get() = BLOCK_SIZE_BYTES

    override fun update(byte: Byte): Poly1305 = apply {
        singleByte[0] = byte
        update(singleByte)
    }

    public override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Poly1305 = apply {
        var copied = 0
        val length = endIndex - startIndex
        while (copied < length) {
            val toCopy = min(length - copied, BLOCK_SIZE_BYTES - blockOffset)
            source.copyInto(block, blockOffset, startIndex + copied, startIndex + copied + toCopy)
            blockOffset += toCopy
            copied += toCopy
            if (blockOffset == block.size) {
                processBlock(false)
                blockOffset = 0
            }
        }
    }

    private fun processBlock(partial: Boolean) {
        val hiBit = if (partial) 0u else 1u shl 24

        val r0 = r[0].toInt().toULong()
        val r1 = r[1].toInt().toULong()
        val r2 = r[2].toInt().toULong()
        val r3 = r[3].toInt().toULong()
        val r4 = r[4].toInt().toULong()

        val s1 = r1 * 5u
        val s2 = r2 * 5u
        val s3 = r3 * 5u
        val s4 = r4 * 5u

        var h0 = h[0]
        var h1 = h[1]
        var h2 = h[2]
        var h3 = h[3]
        var h4 = h[4]

        h0 += block.getUIntLe(0) and 0x3FF_FFFFu
        h1 += ((block.getUIntLe(3) shr 2) and 0x3FF_FFFFu)
        h2 += ((block.getUIntLe(6) shr 4) and 0x3FF_FFFFu)
        h3 += ((block.getUIntLe(9) shr 6) and 0x3FF_FFFFu)
        h4 += ((block.getUIntLe(12) shr 8) or hiBit)

        val d0 = (h0.toULong() * r0) +
                (h1.toULong() * s4) +
                (h2.toULong() * s3) +
                (h3.toULong() * s2) +
                (h4.toULong() * s1)

        var d1 = (h0.toULong() * r1) +
                (h1.toULong() * r0) +
                (h2.toULong() * s4) +
                (h3.toULong() * s3) +
                (h4.toULong() * s2)

        var d2 = (h0.toULong() * r2) +
                (h1.toULong() * r1) +
                (h2.toULong() * r0) +
                (h3.toULong() * s4) +
                (h4.toULong() * s3)

        var d3 = (h0.toULong() * r3) +
                (h1.toULong() * r2) +
                (h2.toULong() * r1) +
                (h3.toULong() * r0) +
                (h4.toULong() * s4)

        var d4 = (h0.toULong() * r4) +
                (h1.toULong() * r3) +
                (h2.toULong() * r2) +
                (h3.toULong() * r1) +
                (h4.toULong() * r0)

        var c = (d0 shr 26).toUInt()
        h0 = d0.toUInt() and 0x3FF_FFFFu
        d1 += c

        c = (d1 shr 26).toUInt()
        h1 = d1.toUInt() and 0x3FF_FFFFu
        d2 += c

        c = (d2 shr 26).toUInt()
        h2 = d2.toUInt() and 0x3FF_FFFFu
        d3 += c

        c = (d3 shr 26).toUInt()
        h3 = d3.toUInt() and 0x3FF_FFFFu
        d4 += c

        c = (d4 shr 26).toUInt()
        h4 = d4.toUInt() and 0x3FF_FFFFu
        h0 += c * 5u

        c = (h0 shr 26)
        h0 = h0 and 0x3FF_FFFFu
        h1 += c

        h[0] = h0
        h[1] = h1
        h[2] = h2
        h[3] = h3
        h[4] = h4
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        if (blockOffset > 0) {
            block[blockOffset] = 1
            if (blockOffset + 1 < block.size) {
                block.fill(0, blockOffset + 1, block.size)
            }
            processBlock(true)
        }

        var h0 = h[0]
        var h1 = h[1]
        var h2 = h[2]
        var h3 = h[3]
        var h4 = h[4]

        var c = h1 shr 26
        h1 = h1 and 0x3FF_FFFFu
        h2 += c

        c = h2 shr 26
        h2 = h2 and 0x3FF_FFFFu
        h3 += c

        c = h3 shr 26
        h3 = h3 and 0x3FF_FFFFu
        h4 += c

        c = h4 shr 26
        h4 = h4 and 0x3FF_FFFFu
        h0 += c * 5u

        c = h0 shr 26
        h0 = h0 and 0x3FF_FFFFu
        h1 += c

        var g0 = h0 + 5u
        c = g0 shr 26
        g0 = g0 and 0x3FF_FFFFu

        var g1 = h1 + c
        c = g1 shr 26
        g1 = g1 and 0x3FF_FFFFu

        var g2 = h2 + c
        c = g2 shr 26
        g2 = g2 and 0x3FF_FFFFu

        var g3 = h3 + c
        c = g3 shr 26
        g3 = g3 and 0x3FF_FFFFu

        var g4 = h4 + c - (1u shl 26)

        var mask = (g4 shr (31)) - 1u
        g0 = g0 and mask
        g1 = g1 and mask
        g2 = g2 and mask
        g3 = g3 and mask
        g4 = g4 and mask
        mask = mask.inv()
        h0 = (h0 and mask) or g0
        h1 = (h1 and mask) or g1
        h2 = (h2 and mask) or g2
        h3 = (h3 and mask) or g3
        h4 = (h4 and mask) or g4

        h0 = h0 or (h1 shl 26)
        h1 = ((h1 shr 6) or (h2 shl 20))
        h2 = ((h2 shr 12) or (h3 shl 14))
        h3 = ((h3 shr 18) or (h4 shl 8))

        var f = h0.toULong() + pad[0].toULong()
        h0 = f.toUInt()

        f = h1.toULong() + pad[1].toULong() + (f shr 32)
        h1 = f.toUInt()

        f = h2.toULong() + pad[2].toULong() + (f shr 32)
        h2 = f.toUInt()

        f = h3.toULong() + pad[3].toULong() + (f shr 32)
        h3 = f.toUInt()

        destination.setUIntLe(destinationOffset, h0)
        destination.setUIntLe(destinationOffset + 4, h1)
        destination.setUIntLe(destinationOffset + 8, h2)
        destination.setUIntLe(destinationOffset + 12, h3)

        reset()
    }

    override fun reset() {
        h.fill(0u)
        block.fill(0)
        blockOffset = 0
    }

    public companion object {
        public const val BLOCK_SIZE_BYTES: Int = 16

        private inline fun ByteArray.getUIntLe(index: Int) = getIntLe(index).toUInt()

        private fun ByteArray.getIntLe(index: Int): Int {
            return ((this[index].toInt() and 0xFF) or
                    ((this[index + 1].toInt() and 0xFF) shl 8) or
                    ((this[index + 2].toInt() and 0xFF) shl 16) or
                    ((this[index + 3].toInt() and 0xFF) shl 24))
        }

        private inline fun ByteArray.setUIntLe(index: Int, value: UInt) {
            setIntLe(index, value.toInt())
        }

        private fun ByteArray.setIntLe(index: Int, value: Int) {
            this[index] = (value and 0xFF).toByte()
            this[index + 1] = ((value shr 8) and 0xFF).toByte()
            this[index + 2] = ((value shr 16) and 0xFF).toByte()
            this[index + 3] = ((value shr 24) and 0xFF).toByte()
        }
    }
}
