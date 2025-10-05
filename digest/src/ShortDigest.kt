package io.github.andreypfau.kotlinx.crypto

public interface ShortDigest : Digest {
    override val digestSize: Int
        get() = Short.SIZE_BYTES

    override val blockSize: Int
        get() = 1

    public fun shortDigest(): Short
}
