package io.github.andreypfau.kotlinx.crypto.sha2

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import kotlinx.io.Buffer
import kotlinx.io.RawSink
import java.security.MessageDigest
import kotlin.math.min

public actual class SHA512 : Digest {
    override val digestSize: Int get() = 64

    private val jvmDigest = MessageDigest.getInstance("SHA-512")

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        jvmDigest.digest(destination, destinationOffset, digestSize)
    }

    override fun digest(sink: RawSink) {
        val buffer = Buffer()
        buffer.write(digest())
        sink.write(buffer, digestSize.toLong())
    }

    override fun write(source: Buffer, byteCount: Long) {
        val tempBuffer = ByteArray(128)
        var remaining = byteCount
        while (remaining > 0) {
            val read = source.readAtMostTo(tempBuffer, 0, min(remaining, tempBuffer.size.toLong()).toInt())
            write(tempBuffer, 0, read)
            remaining -= read
        }
    }

    override fun write(source: ByteArray, startIndex: Int, endIndex: Int) {
        jvmDigest.update(source, startIndex, endIndex - startIndex)
    }

    override fun reset() {
        jvmDigest.reset()
    }
}
