package io.github.andreypfau.kotlinx.crypto.digest

public interface IntDigest : Digest {
    override val digestSize: Int
        get() = Int.SIZE_BYTES

    public fun intDigest(): Int
}
