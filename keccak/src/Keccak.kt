package io.github.andreypfau.kotlinx.crypto

import kotlin.experimental.or
import kotlin.math.min

public open class Keccak(
    bitSize: Int
) : Digest {
    public constructor() : this(256)

    private val rate = 1600 - (bitSize shl 1)
    private val state = LongArray(25)
    private val dataQueue = ByteArray(192)
    private var bitsInQueue = 0
    private var squeezing = false
    protected val fixedOutputLength: Int = (1600 - rate) / 2

    override val digestSize: Int = fixedOutputLength / 8
    override val blockSize: Int
        get() = rate
    override val algorithmName: String
        get() = "Keccak-$fixedOutputLength"

    override fun update(byte: Byte): Keccak = apply {
        absorbBits(byte.toInt(), 8)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Keccak = apply {
        val bytesInQueue = bitsInQueue ushr 3
        val rateBytes = rate ushr 3
        val available = rateBytes - bytesInQueue
        val len = endIndex - startIndex
        if (len < available) {
            source.copyInto(dataQueue, bytesInQueue, startIndex, endIndex)
            bitsInQueue += len shl 3
            return@apply
        }
        var count = 0
        if (bytesInQueue > 0) {
            source.copyInto(dataQueue, bytesInQueue, startIndex, startIndex + available)
            count += available
            keccakAbsorb(dataQueue, 0)
        }

        var remaining: Int
        while (((len - count).also { remaining = it }) >= rateBytes) {
            keccakAbsorb(source, startIndex + count)
            count += rateBytes
        }
        source.copyInto(dataQueue, 0, startIndex + count, startIndex + count + remaining)
        bitsInQueue = remaining shl 3
    }

    override fun digest(): ByteArray {
        val result = ByteArray(digestSize)
        digest(result)
        return result
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        squeeze(destination, destinationOffset, fixedOutputLength)
        reset()
    }

    override fun reset() {
        bitsInQueue = 0
        squeezing = false
        state.fill(0)
        dataQueue.fill(0)
    }

    protected fun absorbBits(data: Int, bits: Int) {
        val mask = (1 shl bits) - 1
        dataQueue[bitsInQueue ushr 3] = (data and mask).toByte()
        bitsInQueue += bits
    }

    private fun padAndSwitchToSqueezingPhase() {
        val i = bitsInQueue ushr 3
        dataQueue[i] = dataQueue[i] or (1 shl (bitsInQueue and 7)).toByte()
        if (++bitsInQueue == rate) {
            keccakAbsorb(dataQueue, 0)
        } else {
            val full = bitsInQueue ushr 6
            val partial = bitsInQueue and 63
            for (k in 0 until full) {
                state[k] = state[k] xor dataQueue.getLeLongAt(k shl 3)
            }
            if (partial > 0) {
                val mask = (1L shl partial) - 1
                state[full] = state[full] xor (dataQueue.getLeLongAt(full shl 3) and mask)
            }
        }
        val j = (rate - 1) ushr 6
        state[j] = state[j] xor (1L shl 63)
        bitsInQueue = 0
        squeezing = true
    }

    protected fun squeeze(output: ByteArray, offset: Int, outputLength: Int) {
        if (!squeezing) {
            padAndSwitchToSqueezingPhase()
        }

        var i = 0
        while (i < outputLength) {
            if (bitsInQueue == 0) {
                keccakExtract()
            }
            val partialBlock = min(outputLength - i, bitsInQueue)
            val startIndex = (rate - bitsInQueue) / 8
            val endIndex = startIndex + partialBlock / 8
            dataQueue.copyInto(output, offset + (i / 8), startIndex, endIndex)
            bitsInQueue -= partialBlock
            i += partialBlock
        }
    }

    private fun keccakAbsorb(data: ByteArray, offset: Int) {
        val count = rate ushr 6
        for (i in 0 until count) {
            val index = i shl 3 // magic number 8
            state[i] = state[i] xor data.getLeLongAt(index + offset)
        }
        keccakF1600(state)
    }

    private fun keccakExtract() {
        keccakF1600(state)
        for (i in 0 until (rate ushr 6)) {
            dataQueue.setLeLongAt(i shl 3, state[i])
        }
        bitsInQueue = rate
    }

    public companion object {
        private val KeccakRoundConstants = longArrayOf(
            0x0000000000000001L, 0x0000000000008082L,
            -0x7fffffffffff7f76L, -0x7fffffff7fff8000L, 0x000000000000808bL, 0x0000000080000001L, -0x7fffffff7fff7f7fL,
            -0x7fffffffffff7ff7L, 0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, -0x7fffffffffffff75L, -0x7fffffffffff7f77L, -0x7fffffffffff7ffdL, -0x7fffffffffff7ffeL,
            -0x7fffffffffffff80L, 0x000000000000800aL, -0x7fffffff7ffffff6L, -0x7fffffff7fff7f7fL, -0x7fffffffffff7f80L,
            0x0000000080000001L, -0x7fffffff7fff7ff8L
        )

        private fun keccakF1600(a: LongArray) {
            for (i in 0..23) {
                // theta
                var c0 = a[0] xor a[5] xor a[10] xor a[15] xor a[20]
                var c1 = a[1] xor a[6] xor a[11] xor a[16] xor a[21]
                val c2 = a[2] xor a[7] xor a[12] xor a[17] xor a[22]
                val c3 = a[3] xor a[8] xor a[13] xor a[18] xor a[23]
                val c4 = a[4] xor a[9] xor a[14] xor a[19] xor a[24]

                val d1 = (c1 shl 1 or (c1 ushr -1)) xor c4
                val d2 = (c2 shl 1 or (c2 ushr -1)) xor c0
                val d3 = (c3 shl 1 or (c3 ushr -1)) xor c1
                val d4 = (c4 shl 1 or (c4 ushr -1)) xor c2
                val d0 = (c0 shl 1 or (c0 ushr -1)) xor c3

                a[0] = a[0] xor d1
                a[5] = a[5] xor d1
                a[10] = a[10] xor d1
                a[15] = a[15] xor d1
                a[20] = a[20] xor d1
                a[1] = a[1] xor d2
                a[6] = a[6] xor d2
                a[11] = a[11] xor d2
                a[16] = a[16] xor d2
                a[21] = a[21] xor d2
                a[2] = a[2] xor d3
                a[7] = a[7] xor d3
                a[12] = a[12] xor d3
                a[17] = a[17] xor d3
                a[22] = a[22] xor d3
                a[3] = a[3] xor d4
                a[8] = a[8] xor d4
                a[13] = a[13] xor d4
                a[18] = a[18] xor d4
                a[23] = a[23] xor d4
                a[4] = a[4] xor d0
                a[9] = a[9] xor d0
                a[14] = a[14] xor d0
                a[19] = a[19] xor d0
                a[24] = a[24] xor d0

                // rho/pi
                c1 = a[1] shl 1 or (a[1] ushr 63)
                a[1] = a[6] shl 44 or (a[6] ushr 20)
                a[6] = a[9] shl 20 or (a[9] ushr 44)
                a[9] = a[22] shl 61 or (a[22] ushr 3)
                a[22] = a[14] shl 39 or (a[14] ushr 25)
                a[14] = a[20] shl 18 or (a[20] ushr 46)
                a[20] = a[2] shl 62 or (a[2] ushr 2)
                a[2] = a[12] shl 43 or (a[12] ushr 21)
                a[12] = a[13] shl 25 or (a[13] ushr 39)
                a[13] = a[19] shl 8 or (a[19] ushr 56)
                a[19] = a[23] shl 56 or (a[23] ushr 8)
                a[23] = a[15] shl 41 or (a[15] ushr 23)
                a[15] = a[4] shl 27 or (a[4] ushr 37)
                a[4] = a[24] shl 14 or (a[24] ushr 50)
                a[24] = a[21] shl 2 or (a[21] ushr 62)
                a[21] = a[8] shl 55 or (a[8] ushr 9)
                a[8] = a[16] shl 45 or (a[16] ushr 19)
                a[16] = a[5] shl 36 or (a[5] ushr 28)
                a[5] = a[3] shl 28 or (a[3] ushr 36)
                a[3] = a[18] shl 21 or (a[18] ushr 43)
                a[18] = a[17] shl 15 or (a[17] ushr 49)
                a[17] = a[11] shl 10 or (a[11] ushr 54)
                a[11] = a[7] shl 6 or (a[7] ushr 58)
                a[7] = a[10] shl 3 or (a[10] ushr 61)
                a[10] = c1

                // chi
                c0 = a[0] xor (a[1].inv() and a[2])
                c1 = a[1] xor (a[2].inv() and a[3])
                a[2] = a[2] xor (a[3].inv() and a[4])
                a[3] = a[3] xor (a[4].inv() and a[0])
                a[4] = a[4] xor (a[0].inv() and a[1])
                a[0] = c0
                a[1] = c1

                c0 = a[5] xor (a[6].inv() and a[7])
                c1 = a[6] xor (a[7].inv() and a[8])
                a[7] = a[7] xor (a[8].inv() and a[9])
                a[8] = a[8] xor (a[9].inv() and a[5])
                a[9] = a[9] xor (a[5].inv() and a[6])
                a[5] = c0
                a[6] = c1

                c0 = a[10] xor (a[11].inv() and a[12])
                c1 = a[11] xor (a[12].inv() and a[13])
                a[12] = a[12] xor (a[13].inv() and a[14])
                a[13] = a[13] xor (a[14].inv() and a[10])
                a[14] = a[14] xor (a[10].inv() and a[11])
                a[10] = c0
                a[11] = c1

                c0 = a[15] xor (a[16].inv() and a[17])
                c1 = a[16] xor (a[17].inv() and a[18])
                a[17] = a[17] xor (a[18].inv() and a[19])
                a[18] = a[18] xor (a[19].inv() and a[15])
                a[19] = a[19] xor (a[15].inv() and a[16])
                a[15] = c0
                a[16] = c1

                c0 = a[20] xor (a[21].inv() and a[22])
                c1 = a[21] xor (a[22].inv() and a[23])
                a[22] = a[22] xor (a[23].inv() and a[24])
                a[23] = a[23] xor (a[24].inv() and a[20])
                a[24] = a[24] xor (a[20].inv() and a[21])
                a[20] = c0
                a[21] = c1

                // iota
                a[0] = a[0] xor KeccakRoundConstants[i]
            }
        }

        private fun ByteArray.getLeLongAt(offset: Int): Long {
            return (this[offset].toLong() and 0xFF) or
                    ((this[offset + 1].toLong() and 0xFF) shl 8) or
                    ((this[offset + 2].toLong() and 0xFF) shl 16) or
                    ((this[offset + 3].toLong() and 0xFF) shl 24) or
                    ((this[offset + 4].toLong() and 0xFF) shl 32) or
                    ((this[offset + 5].toLong() and 0xFF) shl 40) or
                    ((this[offset + 6].toLong() and 0xFF) shl 48) or
                    ((this[offset + 7].toLong() and 0xFF) shl 56)
        }

        private fun ByteArray.setLeLongAt(offset: Int, value: Long) {
            this[offset] = value.toByte()
            this[offset + 1] = (value ushr 8).toByte()
            this[offset + 2] = (value ushr 16).toByte()
            this[offset + 3] = (value ushr 24).toByte()
            this[offset + 4] = (value ushr 32).toByte()
            this[offset + 5] = (value ushr 40).toByte()
            this[offset + 6] = (value ushr 48).toByte()
            this[offset + 7] = (value ushr 56).toByte()
        }
    }
}
