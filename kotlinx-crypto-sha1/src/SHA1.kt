package io.github.andreypfau.kotlinx.crypto.sha1

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.digest.plusAssign

public expect class SHA1 public constructor() : Digest

public fun sha1(data: ByteArray): ByteArray {
    val sha1 = SHA1()
    sha1 += data
    return sha1.digest()
}
