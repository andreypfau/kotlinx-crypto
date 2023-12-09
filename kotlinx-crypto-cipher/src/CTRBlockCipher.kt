package io.github.andreypfau.kotlinx.crypto.cipher

import kotlin.experimental.xor

public class CTRBlockCipher(
    cipher: BlockCipher,
    iv: ByteArray
) : StreamBlockCipher(cipher) {
    init {
        require(iv.size == cipher.blockSize) {
            "IV length must equal block size"
        }
    }
    private val iv = iv.copyOf()
    private val counter = ByteArray(cipher.blockSize)
    private val counterOut = ByteArray(cipher.blockSize)
    private var byteCount = 0

    init {
        reset()
    }

    override val blockSize: Int
        get() = cipher.blockSize
    override val algorithmName: String
        get() = "${cipher.algorithmName}/CTR"

    override fun decryptBlock(source: ByteArray, destination: ByteArray, destinationOffset: Int, startIndex: Int): Int {
        return encryptBlock(source, destination, destinationOffset, startIndex)
    }

    override fun encryptBlock(source: ByteArray, destination: ByteArray, destinationOffset: Int, startIndex: Int): Int {
        if (byteCount != 0) {
            return processBytes(source, destination, destinationOffset, startIndex, startIndex + blockSize)
        }
        cipher.encryptBlock(counter, counterOut)
        for (i in 0 until blockSize) {
            destination[destinationOffset + i] = source[startIndex + i] xor counterOut[i]
        }
        incrementCounter()
        return blockSize
    }

    override fun processBytes(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int
    ): Int {
        val len = endIndex - startIndex
        for (i in 0 until len) {
            var next: Byte
            if (byteCount == 0) {
                cipher.encryptBlock(counter, counterOut)
                next = source[startIndex + i] xor counterOut[byteCount++]
            } else {
                next = source[startIndex + i] xor counterOut[byteCount++]
                if (byteCount == counter.size) {
                    byteCount = 0
                    incrementCounter()
                }
            }
            destination[destinationOffset + i] = next
        }
        return endIndex - startIndex
    }

    private fun incrementCounter() {
        var i = counter.size
        while (--i >= 0) {
            if (++counter[i] != 0.toByte()) {
                break
            }
        }
    }

    override fun calculateByte(byte: Byte): Byte {
        if (byteCount == 0) {
            cipher.encryptBlock(counter, counterOut)
            return counterOut[byteCount++] xor byte
        }
        val rv = counterOut[byteCount++] xor byte
        if (byteCount == counter.size) {
            byteCount = 0
            incrementCounter()
        }
        return rv
    }

    override fun reset() {
        iv.copyInto(counter)
        cipher.reset()
        byteCount = 0
    }
}
