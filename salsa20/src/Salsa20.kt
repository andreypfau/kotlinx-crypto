package io.github.andreypfau.kotlinx.crypto

import kotlinx.io.Buffer
import kotlinx.io.RawSink
import kotlinx.io.RawSource
import kotlin.experimental.xor

public open class Salsa20(
    public val rounds: Int,
    key: ByteArray,
    iv: ByteArray
) : StreamCipher, SkippingCipher {
    public constructor(key: ByteArray, iv: ByteArray) : this(DEFAULT_ROUNDS, key, iv)

    protected val state: IntArray = IntArray(STATE_SIZE)
    protected val x: IntArray = IntArray(STATE_SIZE)
    private val keyStream = ByteArray(STATE_SIZE * Int.SIZE_BYTES)
    private var index = 0

    init {
        setKey(key, iv)
        seekTo(0)
    }

    override val algorithmName: String = "Salsa20${if (rounds != DEFAULT_ROUNDS) "/$rounds" else ""}"
    override val position: Long
        get() = counter * 64 + index

    protected open var counter: Long
        get() = (state[9].toLong() shl 32) or (state[8].toLong() and 0xffffffffL)
        set(value) {
            state[9] = (value ushr 32).toInt()
            state[8] = value.toInt()
        }

    override fun returnByte(input: Byte): Byte {
        val output = (input xor keyStream[index])
        index = (index + 1) and 63
        if (index == 0) {
            counter++
            generateKeyStream(keyStream)
        }
        return output
    }

    override fun processBytes(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int
    ): Int {
        val length = endIndex - startIndex
        for (i in 0 until length) {
            destination[destinationOffset + i] = (source[startIndex + i] xor keyStream[index])
            index = (index + 1) and 63
            if (index == 0) {
                counter++
                generateKeyStream(keyStream)
            }
        }
        return length
    }

    override fun processBytes(
        source: RawSource,
        destination: RawSink,
        byteCount: Long
    ): Long {
        val buffer = Buffer()
        val length = source.readAtMostTo(buffer, byteCount)
        for (i in 0 until length) {
            buffer.writeByte(returnByte(buffer.readByte()))
        }
        destination.write(buffer, length)
        return length
    }

    override fun skip(numberOfBytes: Long): Long {
        if (numberOfBytes >= 0) {
            var remaining = numberOfBytes
            if (remaining >= 64) {
                val count = remaining / 64
                counter += count
                remaining -= count * 64
            }
            val oldIndex = index
            index = (index + remaining.toInt()) and 63
            if (index < oldIndex) {
                counter++
            }
        } else {
            var remaining = -numberOfBytes
            if (remaining >= 64) {
                val count = remaining / 64
                counter -= count
                remaining -= count * 64
            }
            for (i in 0 until remaining) {
                if (index == 0) {
                    counter--
                }
                index = (index - 1) and 63
            }
        }
        generateKeyStream(keyStream)
        return numberOfBytes
    }


    override fun seekTo(position: Long): Long {
        reset()
        return skip(position)
    }

    override fun reset() {
        index = 0
        counter = 0
        generateKeyStream(keyStream)
    }

    protected open fun generateKeyStream(output: ByteArray) {
        processBlock(rounds, state, x)
        x.forEachIndexed { index, i ->
            output.setIntLeAt(index shl 2, i)
        }
    }

    protected open fun setKey(key: ByteArray, iv: ByteArray) {
        if (key.isNotEmpty()) {
            val tsOffset = (key.size - 16) / 4
            state[0] = TAU_SIGMA[tsOffset]
            state[1] = key.getIntLeAt(0)
            state[2] = key.getIntLeAt(4)
            state[3] = key.getIntLeAt(8)
            state[4] = key.getIntLeAt(12)
            state[5] = TAU_SIGMA[tsOffset + 1]

            state[10] = TAU_SIGMA[tsOffset + 2]
            state[11] = key.getIntLeAt(key.size - 16)
            state[12] = key.getIntLeAt(key.size - 12)
            state[13] = key.getIntLeAt(key.size - 8)
            state[14] = key.getIntLeAt(key.size - 4)
            state[15] = TAU_SIGMA[tsOffset + 3]
        }

        state[6] = iv.getIntLeAt(0)
        state[7] = iv.getIntLeAt(4)
    }

    public companion object {
        public const val DEFAULT_ROUNDS: Int = 20
        private const val STATE_SIZE: Int = 16
        private val TAU = "expand 16-byte k".encodeToByteArray().let { bytes ->
            IntArray(4) {
                bytes.getIntLeAt(it shl 2)
            }
        }
        private val SIGMA = "expand 32-byte k".encodeToByteArray().let { bytes ->
            IntArray(4) {
                bytes.getIntLeAt(it shl 2)
            }
        }
        private val TAU_SIGMA = TAU + SIGMA

        public fun processBlock(rounds: Int, input: IntArray, x: IntArray) {
            input.copyInto(x, 0, 0, 16)
            for (i in rounds downTo 1 step 2) {
                // column rounds
                x[4] = x[4] xor (x[0] + x[12]).rotateLeft(7)
                x[8] = x[8] xor (x[4] + x[0]).rotateLeft(9)
                x[12] = x[12] xor (x[8] + x[4]).rotateLeft(13)
                x[0] = x[0] xor (x[12] + x[8]).rotateLeft(18)
                x[9] = x[9] xor (x[5] + x[1]).rotateLeft(7)
                x[13] = x[13] xor (x[9] + x[5]).rotateLeft(9)
                x[1] = x[1] xor (x[13] + x[9]).rotateLeft(13)
                x[5] = x[5] xor (x[1] + x[13]).rotateLeft(18)
                x[14] = x[14] xor (x[10] + x[6]).rotateLeft(7)
                x[2] = x[2] xor (x[14] + x[10]).rotateLeft(9)
                x[6] = x[6] xor (x[2] + x[14]).rotateLeft(13)
                x[10] = x[10] xor (x[6] + x[2]).rotateLeft(18)
                x[3] = x[3] xor (x[15] + x[11]).rotateLeft(7)
                x[7] = x[7] xor (x[3] + x[15]).rotateLeft(9)
                x[11] = x[11] xor (x[7] + x[3]).rotateLeft(13)
                x[15] = x[15] xor (x[11] + x[7]).rotateLeft(18)

                // diagonal rounds
                x[1] = x[1] xor (x[0] + x[3]).rotateLeft(7)
                x[2] = x[2] xor (x[1] + x[0]).rotateLeft(9)
                x[3] = x[3] xor (x[2] + x[1]).rotateLeft(13)
                x[0] = x[0] xor (x[3] + x[2]).rotateLeft(18)
                x[6] = x[6] xor (x[5] + x[4]).rotateLeft(7)
                x[7] = x[7] xor (x[6] + x[5]).rotateLeft(9)
                x[4] = x[4] xor (x[7] + x[6]).rotateLeft(13)
                x[5] = x[5] xor (x[4] + x[7]).rotateLeft(18)
                x[11] = x[11] xor (x[10] + x[9]).rotateLeft(7)
                x[8] = x[8] xor (x[11] + x[10]).rotateLeft(9)
                x[9] = x[9] xor (x[8] + x[11]).rotateLeft(13)
                x[10] = x[10] xor (x[9] + x[8]).rotateLeft(18)
                x[12] = x[12] xor (x[15] + x[14]).rotateLeft(7)
                x[13] = x[13] xor (x[12] + x[15]).rotateLeft(9)
                x[14] = x[14] xor (x[13] + x[12]).rotateLeft(13)
                x[15] = x[15] xor (x[14] + x[13]).rotateLeft(18)
            }

            x[0] += input[0]
            x[1] += input[1]
            x[2] += input[2]
            x[3] += input[3]
            x[4] += input[4]
            x[5] += input[5]
            x[6] += input[6]
            x[7] += input[7]
            x[8] += input[8]
            x[9] += input[9]
            x[10] += input[10]
            x[11] += input[11]
            x[12] += input[12]
            x[13] += input[13]
            x[14] += input[14]
            x[15] += input[15]
        }

        private fun ByteArray.getIntLeAt(index: Int): Int {
            return (this[index].toInt() and 0xff) or
                    ((this[index + 1].toInt() and 0xff) shl 8) or
                    ((this[index + 2].toInt() and 0xff) shl 16) or
                    ((this[index + 3].toInt() and 0xff) shl 24)
        }

        private fun ByteArray.setIntLeAt(index: Int, value: Int) {
            this[index] = value.toByte()
            this[index + 1] = (value ushr 8).toByte()
            this[index + 2] = (value ushr 16).toByte()
            this[index + 3] = (value ushr 24).toByte()
        }
    }
}
