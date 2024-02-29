package io.github.andreypfau.kotlinx.crypto

public expect class SHA3(
    bitLength: Int
) : Digest {
    public constructor()
}

public class SHA3Impl(
    bitLength: Int
) : Keccak(bitLength), Digest {
    public constructor() : this(256)

    override val algorithmName: String
        get() = "SHA3-$fixedOutputLength"

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        absorbBits(0x02, 2)
        super<Keccak>.digest(destination, destinationOffset)
    }
}
