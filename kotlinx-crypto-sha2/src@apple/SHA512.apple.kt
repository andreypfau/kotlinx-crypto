package io.github.andreypfau.kotlinx.crypto.sha2

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import kotlinx.cinterop.*
import kotlinx.io.Buffer
import kotlinx.io.RawSink
import platform.CoreCrypto.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.math.min
import kotlin.native.ref.createCleaner

@OptIn(ExperimentalForeignApi::class)
public actual class SHA512 : Digest {
    override val digestSize: Int get() = CC_SHA512_DIGEST_LENGTH
    private var ctx = nativeHeap.alloc<CC_SHA512_CTX>().apply {
        CC_SHA512_Init(ptr)
    }

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(this) {
        nativeHeap.free(ctx.ptr)
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
        if (source.isEmpty() && startIndex == 0 && endIndex == 0) {
            return
        }
        source.usePinned { sourcePinned ->
            CC_SHA512_Update(ctx.ptr, sourcePinned.addressOf(startIndex), (endIndex - startIndex).convert())
        }
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        destination.asUByteArray().usePinned { destinationPinned ->
            CC_SHA512_Final(destinationPinned.addressOf(destinationOffset), ctx.ptr)
        }
    }

    override fun digest(sink: RawSink) {
        val buffer = Buffer()
        buffer.write(digest())
        sink.write(buffer, digestSize.toLong())
    }

    override fun reset() {
        nativeHeap.free(ctx.ptr)
        nativeHeap.alloc<CC_SHA512_CTX>().apply {
            CC_SHA512_Init(ptr)
        }
    }
}
