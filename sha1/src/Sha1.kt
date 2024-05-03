package io.github.andreypfau.kotlinx.crypto

public expect class Sha1 public constructor() : Digest {
    public override val digestSize: Int

    public override val blockSize: Int

    public override val algorithmName: String

    public override fun update(byte: Byte): Sha1

    public override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha1

    public override fun digest(): ByteArray

    public override fun digest(destination: ByteArray, destinationOffset: Int)

    public override fun reset()
}

public fun sha1(data: ByteArray): ByteArray {
    val sha1 = Sha1()
    sha1 += data
    return sha1.digest()
}
