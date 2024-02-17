package io.github.andreypfau.kotlinx.crypto.hmac

import io.github.andreypfau.kotlinx.crypto.digest.Digest

public class HMac(
    private val digest: Digest,
    key: ByteArray
) : Digest {
    override val digestSize: Int
        get() = digest.digestSize
    override val blockSize: Int
        get() = digest.blockSize
    override val algorithmName: String
        get() = "${digest.algorithmName}/HMAC"

    private val inputPad = ByteArray(blockSize)
    private val outputBuf = ByteArray(blockSize + digestSize)

    init {
        digest.reset()
        var keyLength = key.size
        if (keyLength > blockSize) {
            digest.update(key)
            digest.digest(inputPad)
            keyLength = digestSize
        } else {
            key.copyInto(inputPad)
        }

        inputPad.fill(0, keyLength)
        inputPad.copyInto(outputBuf)

        inputPad.indices.forEach {
            inputPad[it] = (inputPad[it].toInt() xor IPAD).toByte()
        }
        outputBuf.indices.forEach {
            outputBuf[it] = (outputBuf[it].toInt() xor OPAD).toByte()
        }
        digest.update(inputPad)
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        val blockSize = blockSize
        digest.digest(outputBuf, blockSize)
        digest.update(outputBuf)
        digest.digest(destination, destinationOffset)
        outputBuf.fill(0, blockSize)
        digest.update(inputPad)
    }

    override fun reset() {
        digest.reset()
        digest.update(inputPad)
    }

    override fun digest(): ByteArray {
        return digest.digest()
    }

    override fun updateByte(byte: Byte) {
        digest.updateByte(byte)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        digest.update(source, startIndex, endIndex)
    }

    public companion object {
        private const val IPAD = 0x36
        private const val OPAD = 0x5C
    }
}
