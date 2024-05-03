package io.github.andreypfau.kotlinx.crypto

import org.junit.Test

class Crc32JvmTest {
    @Test
    fun foo() {
        val input = "ab".toByteArray()
        val crc32jdk = java.util.zip.CRC32C()
        crc32jdk.update(input)

        val crC32C = CRC32CImpl()
        crC32C += input

        val crc32cDel = CRC32C()
        crc32cDel += input
    }
}
