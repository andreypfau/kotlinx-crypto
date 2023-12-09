package io.github.andreypfau.kotlinx.crypto.digest

import kotlinx.io.RawSink

public interface Digest : RawSink {
    public val digestSize: Int

    public fun write(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size)

    public fun digest(): ByteArray = ByteArray(digestSize).apply {
        digest(this)
    }

    public fun digest(destination: ByteArray, destinationOffset: Int = 0)

    public fun digest(sink: RawSink)

    override fun flush() {
    }

    override fun close() {
        reset()
    }

    public fun reset()
}

public inline operator fun Digest.plusAssign(byteArray: ByteArray): Unit = write(byteArray)
