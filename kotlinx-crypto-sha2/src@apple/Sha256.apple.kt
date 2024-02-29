package io.github.andreypfau.kotlinx.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

@OptIn(ExperimentalForeignApi::class)
public actual class Sha256 : Digest {
    override val digestSize: Int get() = CC_SHA256_DIGEST_LENGTH

    override val blockSize: Int get() = CC_SHA256_BLOCK_BYTES

    override val algorithmName: String get() = Sha256Impl.ALGORITHM_NAME

    private var ctx = nativeHeap.alloc<CC_SHA256_CTX>().apply {
        CC_SHA256_Init(ptr)
    }

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(this) {
        nativeHeap.free(ctx.ptr)
    }

    override fun update(byte: Byte): Sha256 = apply {
        memScoped {
            val bytePtr = alloc<ByteVar>()
            bytePtr.value = byte
            CC_SHA256_Update(ctx.ptr, bytePtr.ptr, 1.convert())
        }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha256 = apply {
        if (source.isEmpty() && startIndex == 0 && endIndex == 0) {
            return@apply
        }
        source.usePinned { sourcePinned ->
            CC_SHA256_Update(ctx.ptr, sourcePinned.addressOf(startIndex), (endIndex - startIndex).convert())
        }
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        destination.asUByteArray().usePinned { destinationPinned ->
            CC_SHA256_Final(destinationPinned.addressOf(destinationOffset), ctx.ptr)
        }
        reset()
    }

    override fun reset() {
        nativeHeap.free(ctx.ptr)
        ctx = nativeHeap.alloc<CC_SHA256_CTX>().apply {
            CC_SHA256_Init(ptr)
        }
    }
}
