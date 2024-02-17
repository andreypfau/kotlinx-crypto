package io.github.andreypfau.kotlinx.crypto.cipher

import kotlinx.io.RawSink
import kotlinx.io.RawSource

public interface StreamCipher {
    public val algorithmName: String

    public fun returnByte(input: Byte): Byte

    public fun processBytes(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int = 0,
        startIndex: Int = 0,
        endIndex: Int = source.size
    ): Int

    public fun processBytes(
        source: RawSource,
        destination: RawSink,
        byteCount: Long
    ): Long

    public fun reset()
}
