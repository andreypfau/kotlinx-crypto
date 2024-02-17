package io.github.andreypfau.kotlinx.crypto.aes

import io.github.andreypfau.kotlinx.crypto.cipher.CTRBlockCipher
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals

class AESCtrTest {
    val commonCounter = ubyteArrayOf(
        0xf0u, 0xf1u, 0xf2u, 0xf3u, 0xf4u, 0xf5u, 0xf6u, 0xf7u, 0xf8u, 0xf9u, 0xfau, 0xfbu, 0xfcu, 0xfdu, 0xfeu, 0xffu
    ).asByteArray()

    @Test
    fun testCTRAES128() = testAesCtr(
        commonKey128,
        commonCounter,
        commonInput,
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee".hexToByteArray()
    )

    @Test
    fun testCTRAES192() = testAesCtr(
        commonKey192,
        commonCounter,
        commonInput,
        "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050".hexToByteArray()
    )

    @Test
    fun testCTRAES256() = testAesCtr(
        commonKey256,
        commonCounter,
        commonInput,
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6".hexToByteArray()
    )

    private fun testAesCtr(
        key: ByteArray,
        iv: ByteArray,
        input: ByteArray,
        output: ByteArray
    ) {
        val cipher = AES(key)
        for (j in 0..5 step 5) {
            val plain = input.copyOfRange(0, input.size - j)
            val ctr = CTRBlockCipher(cipher, iv)
            val encrypted = ByteArray(plain.size)
            ctr.processBytes(plain, encrypted)
            val expected = output.copyOfRange(0, output.size - j)
            assertContentEquals(expected, encrypted)
        }

        for (j in 0..5 step 5) {
            val plain = Buffer().apply {
                write(input.copyOfRange(0, input.size - j))
            }
            val ctr = CTRBlockCipher(cipher, iv)
            val encrypted = Buffer()
            ctr.processBytes(plain, encrypted, plain.size)
            val expected = output.copyOfRange(0, output.size - j)
            assertContentEquals(expected, encrypted.readByteArray())
        }

        for (j in 0..7 step 7) {
            val encrypted = output.copyOfRange(0, output.size - j)
            val ctr = CTRBlockCipher(cipher, iv)
            val plain = ByteArray(encrypted.size)
            ctr.processBytes(encrypted, plain)
            val expected = input.copyOfRange(0, input.size - j)
            assertContentEquals(expected, plain)
        }
    }
}
