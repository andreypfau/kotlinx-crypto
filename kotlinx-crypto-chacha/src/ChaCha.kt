package io.github.andreypfau.kotlinx.crypto.chacha

import io.github.andreypfau.kotlinx.crypto.salsa20.Salsa20

public class ChaCha(
    rounds: Int,
    key: ByteArray,
    iv: ByteArray
) : Salsa20(rounds, key, iv) {
    public constructor(key: ByteArray, iv: ByteArray) : this(DEFAULT_ROUNDS, key, iv)

    override val algorithmName: String
        get() = "ChaCha$rounds"

    override var counter: Long
        get() = (state[13].toLong() shl 32) or (state[12].toLong() and 0xffffffffL)
        set(value) {
            state[13] = (value ushr 32).toInt()
            state[12] = value.toInt()
        }

    override fun setKey(key: ByteArray, iv: ByteArray) {
        if (key.isNotEmpty()) {
            val tsOffset = (key.size - 16) / 4
            state[0] = TAU_SIGMA[tsOffset]
            state[1] = TAU_SIGMA[tsOffset + 1]
            state[2] = TAU_SIGMA[tsOffset + 2]
            state[3] = TAU_SIGMA[tsOffset + 3]
            state[4] = key.getIntLeAt(0)
            state[5] = key.getIntLeAt(4)
            state[6] = key.getIntLeAt(8)
            state[7] = key.getIntLeAt(12)
            state[8] = key.getIntLeAt(key.size - 16)
            state[9] = key.getIntLeAt(key.size - 12)
            state[10] = key.getIntLeAt(key.size - 8)
            state[11] = key.getIntLeAt(key.size - 4)
        }

        state[14] = iv.getIntLeAt(0)
        state[15] = iv.getIntLeAt(4)
    }

    override fun generateKeyStream(output: ByteArray) {
        processBlock(rounds, state, x)
        x.forEachIndexed { index, i ->
            output.setIntLeAt(index shl 2, i)
        }
    }

    public companion object {
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
                x[0] += x[4]
                x[12] = (x[12] xor x[0]).rotateLeft(16)
                x[8] += x[12]
                x[4] = (x[4] xor x[8]).rotateLeft(12)
                x[0] += x[4]
                x[12] = (x[12] xor x[0]).rotateLeft(8)
                x[8] += x[12]
                x[4] = (x[4] xor x[8]).rotateLeft(7)
                x[1] += x[5]
                x[13] = (x[13] xor x[1]).rotateLeft(16)
                x[9] += x[13]
                x[5] = (x[5] xor x[9]).rotateLeft(12)
                x[1] += x[5]
                x[13] = (x[13] xor x[1]).rotateLeft(8)
                x[9] += x[13]
                x[5] = (x[5] xor x[9]).rotateLeft(7)
                x[2] += x[6]
                x[14] = (x[14] xor x[2]).rotateLeft(16)
                x[10] += x[14]
                x[6] = (x[6] xor x[10]).rotateLeft(12)
                x[2] += x[6]
                x[14] = (x[14] xor x[2]).rotateLeft(8)
                x[10] += x[14]
                x[6] = (x[6] xor x[10]).rotateLeft(7)
                x[3] += x[7]
                x[15] = (x[15] xor x[3]).rotateLeft(16)
                x[11] += x[15]
                x[7] = (x[7] xor x[11]).rotateLeft(12)
                x[3] += x[7]
                x[15] = (x[15] xor x[3]).rotateLeft(8)
                x[11] += x[15]
                x[7] = (x[7] xor x[11]).rotateLeft(7)
                x[0] += x[5]
                x[15] = (x[15] xor x[0]).rotateLeft(16)
                x[10] += x[15]
                x[5] = (x[5] xor x[10]).rotateLeft(12)
                x[0] += x[5]
                x[15] = (x[15] xor x[0]).rotateLeft(8)
                x[10] += x[15]
                x[5] = (x[5] xor x[10]).rotateLeft(7)
                x[1] += x[6]
                x[12] = (x[12] xor x[1]).rotateLeft(16)
                x[11] += x[12]
                x[6] = (x[6] xor x[11]).rotateLeft(12)
                x[1] += x[6]
                x[12] = (x[12] xor x[1]).rotateLeft(8)
                x[11] += x[12]
                x[6] = (x[6] xor x[11]).rotateLeft(7)
                x[2] += x[7]
                x[13] = (x[13] xor x[2]).rotateLeft(16)
                x[8] += x[13]
                x[7] = (x[7] xor x[8]).rotateLeft(12)
                x[2] += x[7]
                x[13] = (x[13] xor x[2]).rotateLeft(8)
                x[8] += x[13]
                x[7] = (x[7] xor x[8]).rotateLeft(7)
                x[3] += x[4]
                x[14] = (x[14] xor x[3]).rotateLeft(16)
                x[9] += x[14]
                x[4] = (x[4] xor x[9]).rotateLeft(12)
                x[3] += x[4]
                x[14] = (x[14] xor x[3]).rotateLeft(8)
                x[9] += x[14]
                x[4] = (x[4] xor x[9]).rotateLeft(7)
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
