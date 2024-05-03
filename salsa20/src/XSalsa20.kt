package io.github.andreypfau.kotlinx.crypto

public class XSalsa20(
    key: ByteArray,
    iv: ByteArray
) : Salsa20(key, iv) {
    override val algorithmName: String
        get() = "XSalsa20"

    override fun setKey(key: ByteArray, iv: ByteArray) {
        super.setKey(key, iv)

        state[8] = iv.getIntLeAt(8)
        state[9] = iv.getIntLeAt(12)

        val hsalsa20Out = IntArray(state.size)
        processBlock(20, state, hsalsa20Out)

        state[1] = hsalsa20Out[0] - state[0]
        state[2] = hsalsa20Out[5] - state[5]
        state[3] = hsalsa20Out[10] - state[10]
        state[4] = hsalsa20Out[15] - state[15]

        state[11] = hsalsa20Out[6] - state[6]
        state[12] = hsalsa20Out[7] - state[7]
        state[13] = hsalsa20Out[8] - state[8]
        state[14] = hsalsa20Out[9] - state[9]

        state[6] = iv.getIntLeAt(16)
        state[7] = iv.getIntLeAt(20)
    }

    private fun ByteArray.getIntLeAt(index: Int): Int {
        return (this[index].toInt() and 0xff) or
                ((this[index + 1].toInt() and 0xff) shl 8) or
                ((this[index + 2].toInt() and 0xff) shl 16) or
                ((this[index + 3].toInt() and 0xff) shl 24)
    }

    public companion object
}
