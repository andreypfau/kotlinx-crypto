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
public actual class SHA256 : Digest {
    override val digestSize: Int get() = CC_SHA256_DIGEST_LENGTH
    private var sha256Ctx = nativeHeap.alloc<CC_SHA256_CTX>().apply {
        CC_SHA256_Init(ptr)
    }

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(this) {
        nativeHeap.free(sha256Ctx.ptr)
    }

    override fun write(source: Buffer, byteCount: Long) {
        val tempBuffer = ByteArray(64)
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
            CC_SHA256_Update(sha256Ctx.ptr, sourcePinned.addressOf(startIndex), (endIndex - startIndex).convert())
        }
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        destination.asUByteArray().usePinned { destinationPinned ->
            CC_SHA256_Final(destinationPinned.addressOf(destinationOffset), sha256Ctx.ptr)
        }
    }

    override fun digest(sink: RawSink) {
        val buffer = Buffer()
        buffer.write(digest())
        sink.write(buffer, digestSize.toLong())
    }

    override fun reset() {
        nativeHeap.free(sha256Ctx.ptr)
        nativeHeap.alloc<CC_SHA256_CTX>().apply {
            CC_SHA256_Init(ptr)
        }
    }
}
