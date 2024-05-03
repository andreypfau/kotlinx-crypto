package io.github.andreypfau.kotlinx.crypto

public expect class SHA3(
    bitLength: Int
) : Digest {
    public constructor()

    public override val digestSize: Int

    public override val blockSize: Int

    public override val algorithmName: String

    public override fun update(byte: Byte): SHA3

    public override fun update(source: ByteArray, startIndex: Int, endIndex: Int): SHA3

    public override fun digest(): ByteArray

    public override fun digest(destination: ByteArray, destinationOffset: Int)

    public override fun reset()
}

public class SHA3Impl(
    bitLength: Int
) : Keccak(bitLength), Digest {
    public constructor() : this(256)

    override val algorithmName: String
        get() = "SHA3-$fixedOutputLength"

    override fun update(byte: Byte): SHA3Impl = apply {
        update(byte)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): SHA3Impl = apply {
        update(source, startIndex, endIndex)
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        absorbBits(0x02, 2)
        super<Keccak>.digest(destination, destinationOffset)
    }
}
