package io.github.andreypfau.kotlinx.crypto.crc32

import io.github.andreypfau.kotlinx.crypto.digest.IntDigest
import io.github.andreypfau.kotlinx.crypto.digest.plusAssign

public expect class CRC32C public constructor() : IntDigest

public fun crc32c(bytes: ByteArray): Int {
    val crc32c = CRC32C()
    crc32c += bytes
    return crc32c.intDigest()
}

public class CRC32CPure : CRC32Pure(CASTAGNOLI_TABLE), IntDigest
