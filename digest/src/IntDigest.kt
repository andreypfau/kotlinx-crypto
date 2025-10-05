package io.github.andreypfau.kotlinx.crypto

public interface IntDigest : Digest {
    override val digestSize: Int
        get() = Int.SIZE_BYTES

    override val blockSize: Int
        get() = 1

    public fun intDigest(): Int
}
