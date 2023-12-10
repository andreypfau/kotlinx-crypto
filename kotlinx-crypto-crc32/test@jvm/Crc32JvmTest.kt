package io.github.andreypfau.kotlinx.crypto.crc32

import io.github.andreypfau.kotlinx.crypto.digest.plusAssign
import org.junit.Test

class Crc32JvmTest {
    @Test
    fun foo() {
        val input = "ab".toByteArray()
        val crc32jdk = java.util.zip.CRC32C()
        crc32jdk.update(input)
        println(crc32jdk.value.toInt().toHexString())

        val crC32C = CRC32CPure()
        crC32C += input
        println(crC32C.intDigest().toHexString())

        val crc32cDel = CRC32C()
        crc32cDel += input
        println(crc32cDel.intDigest().toHexString())

        println(crc32c(input).toHexString())
    }
}
