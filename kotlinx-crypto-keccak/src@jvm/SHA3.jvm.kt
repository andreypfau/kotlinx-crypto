package io.github.andreypfau.kotlinx.crypto.keccak

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.digest.JvmDigest
import java.security.MessageDigest

public actual class SHA3 public actual constructor(
    bitLength: Int
) : JvmDigest(
    MessageDigest.getInstance("SHA3-$bitLength"),
    "SHA3-$bitLength"
), Digest {
    public actual constructor() : this(256)

    override val blockSize: Int = 1600 - (bitLength shl 1)
}
