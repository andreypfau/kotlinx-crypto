package io.github.andreypfau.kotlinx.crypto.md

import io.github.andreypfau.kotlinx.crypto.digest.Digest

/**
 * base implementation of MD4 family style digest as outlined in "Handbook of Applied Cryptography",
 * pages 344 - 347.
 */
public abstract class GeneralDigest : Digest {
    private val xBuf = ByteArray(4)
    private var xBuffOff = 0
    private var byteCount = 0

    public fun update(input: Byte) {
        xBuf[xBuffOff++] = input
        if (xBuffOff == xBuf.size) {
            processWord(xBuf, 0)
            xBuffOff = 0
        }
        byteCount++
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        val length = endIndex - startIndex
        // fill the current word
        var i = 0
        if (xBuffOff != 0) {
            while (i < length) {
                xBuf[xBuffOff++] = source[startIndex + i++]
                if (xBuffOff == 4) {
                    processWord(xBuf, 0)
                    xBuffOff = 0
                    break
                }
            }
        }

        // process whole words.
        val limit = ((length - i) and 3.inv()) + i
        while (i < limit) {
            processWord(source, startIndex + i)
            i += 4
        }

        // load in the remainder.
        while (i < length) {
            xBuf[xBuffOff++] = source[startIndex + i++]
        }

        byteCount += length
    }

    public fun finish() {
        val bitLength = byteCount.toLong() shl 3

        // add the pad bytes.
        update(128.toByte())

        while (xBuffOff != 0) {
            update(0.toByte())
        }
        processLength(bitLength)
        processBlock()
    }

    override fun reset() {
        byteCount = 0
        xBuffOff = 0
        xBuf.fill(0)
    }

    protected abstract fun processWord(input: ByteArray, offset: Int)
    protected abstract fun processLength(bitLength: Long)
    protected abstract fun processBlock()
}
