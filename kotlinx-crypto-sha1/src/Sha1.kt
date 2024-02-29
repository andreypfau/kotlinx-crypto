package io.github.andreypfau.kotlinx.crypto

public expect class Sha1 public constructor() : Digest {
    override fun update(byte: Byte): Sha1

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha1
}

public fun sha1(data: ByteArray): ByteArray {
    val sha1 = Sha1()
    sha1 += data
    return sha1.digest()
}
