package io.github.andreypfau.kotlinx.crypto.aes

import io.github.andreypfau.kotlinx.crypto.cipher.BlockCipher
import kotlin.test.Test
import kotlin.test.assertContentEquals

class AESTest {
    data class CryptTest(
        val key: String,
        val input: String,
        val output: String
    )

    val encryptTests = arrayOf(
        CryptTest(
            // Appendix B.
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e0370734",
            "3925841d02dc09fbdc118597196a0b32",
        ),
        CryptTest(
            // Appendix C.1.  AES-128
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        CryptTest(
            // Appendix C.2.  AES-192
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        CryptTest(
            // Appendix C.3.  AES-256
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    )

    @Test
    @OptIn(ExperimentalStdlibApi::class)
    fun `test AES encrypt`() {
        encryptTests.forEach {
            val key = it.key.hexToByteArray()
            val input = it.input.hexToByteArray()
            val output = it.output.hexToByteArray()
            testEncrypt(AES(key), input, output)
            testEncrypt(AESImpl(key), input, output)
        }
    }

    @Test
    @OptIn(ExperimentalStdlibApi::class)
    fun `test AES decrypt`() {
        encryptTests.forEach {
            val key = it.key.hexToByteArray()
            val input = it.input.hexToByteArray()
            val output = it.output.hexToByteArray()
            testDecrypt(AES(key), input, output)
            testDecrypt(AESImpl(key), input, output)
        }
    }

    private fun testEncrypt(cipher: BlockCipher, input: ByteArray, output: ByteArray) {
        val actual = ByteArray(input.size)
        cipher.encryptBlock(input, actual)
        assertContentEquals(output, actual)
    }

    private fun testDecrypt(cipher: BlockCipher, input: ByteArray, output: ByteArray) {
        val actual = ByteArray(input.size)
        cipher.decryptBlock(output, actual)
        assertContentEquals(input, actual)
    }
}
