package io.github.andreypfau.kotlinx.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals

class XSalsa20Test {

    @Test
    fun testXSalsa20() {
        assertContentEquals(
            "0bcaef42c447c7627a422ca3930e5543c73cb8fbfb".hexToByteArray(),
            encrypt(
                msg = byteArrayOf(1, 2, 3, 4, 5),
                key = ByteArray(32),
                iv = ByteArray(24)
            )
        )
        assertContentEquals(
            byteArrayOf(1, 2, 3, 4, 5),
            decrypt(
                msg = encrypt(
                    msg = byteArrayOf(1, 2, 3, 4, 5),
                    key = ByteArray(32),
                    iv = ByteArray(24)
                ),
                key = ByteArray(32),
                iv = ByteArray(24)
            )
        )
    }

    private fun assertXSalsa20(
        key: String,
        iv: String,
        si: Int,
        expected: String
    ) {
        val xsalsa20 = XSalsa20(key.hexToByteArray(), iv.hexToByteArray())
        val actual = ByteArray(expected.length / 2)
        xsalsa20.seekTo(si.toLong())
        xsalsa20.processBytes(ByteArray(actual.size), actual)
        assertContentEquals(expected.hexToByteArray(), actual)
    }

    private fun encrypt(
        msg: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray {
        val result = ByteArray(16 + msg.size)
        encrypt(result, 0, msg, 0, msg.size, key, iv)
        return result
    }

    private fun encrypt(
        destination: ByteArray,
        destinationOffset: Int,
        msg: ByteArray,
        startIndex: Int,
        endIndex: Int,
        key: ByteArray,
        iv: ByteArray,
    ) {
        val fullMsg = ByteArray(32 + endIndex - startIndex)
        msg.copyInto(fullMsg, 32, startIndex, endIndex)
        xsalsa20(fullMsg, 0, fullMsg, 0, fullMsg.size, key, iv)
        poly1305(
            fullMsg,
            16,
            fullMsg,
            32,
            fullMsg.size,
            fullMsg
        )
        fullMsg.copyInto(destination, destinationOffset, 16, fullMsg.size)
    }

    private fun decrypt(
        msg: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray {
        val result = ByteArray(msg.size - 16)
        decrypt(result, 0, msg, 0, msg.size, key, iv)
        return result
    }

    private fun decrypt(
        destination: ByteArray,
        destinationOffset: Int,
        msg: ByteArray,
        startIndex: Int,
        endIndex: Int,
        key: ByteArray,
        iv: ByteArray,
    ) {
        val fullMsg = ByteArray(16 + endIndex - startIndex)
        msg.copyInto(fullMsg, 16, startIndex, endIndex)
        poly1305(
            fullMsg,
            16,
            fullMsg,
            32,
            fullMsg.size,
            fullMsg
        )
        xsalsa20(fullMsg, 0, fullMsg, 0, fullMsg.size, key, iv)
        fullMsg.copyInto(destination, destinationOffset, 32, fullMsg.size)
    }

    private fun xsalsa20(
        destination: ByteArray,
        destinationOffset: Int = 0,
        message: ByteArray,
        startIndex: Int = 0,
        endIndex: Int = message.size,
        key: ByteArray,
        iv: ByteArray,
    ) {
        val xSalsa20 = XSalsa20(key, iv)
        xSalsa20.processBytes(message, destination, destinationOffset, startIndex, endIndex)
    }
}
