package io.github.andreypfau.kotlinx.crypto

public expect class CRC32C public constructor() : IntDigest

public fun crc32c(bytes: ByteArray): Int {
    val crc32c = CRC32C()
    crc32c += bytes
    return crc32c.intDigest()
}

public class CRC32CImpl : CRC32Impl(CASTAGNOLI_TABLE), IntDigest
