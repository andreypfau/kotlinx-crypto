package io.github.andreypfau.kotlinx.crypto.cipher

public interface SkippingCipher {
    public val position: Long

    public fun skip(numberOfBytes: Long): Long

    public fun seekTo(position: Long): Long
}
