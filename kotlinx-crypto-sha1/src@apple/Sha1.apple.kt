package io.github.andreypfau.kotlinx.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

@OptIn(ExperimentalForeignApi::class)
public actual class Sha1 : Digest {
    override val digestSize: Int get() = CC_SHA1_DIGEST_LENGTH

    override val blockSize: Int get() = CC_SHA1_BLOCK_BYTES

    override val algorithmName: String get() = Sha1Impl.ALGORITHM_NAME

    private var ctx = nativeHeap.alloc<CC_SHA1_CTX>().apply {
        CC_SHA1_Init(ptr)
    }

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(this) {
        nativeHeap.free(ctx.ptr)
    }

    actual override fun update(byte: Byte): Sha1 = apply {
        memScoped {
            val bytePtr = alloc<ByteVar>()
            bytePtr.value = byte
            CC_SHA1_Update(ctx.ptr, bytePtr.ptr, 1.convert())
        }
    }

    actual override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha1 = apply {
        if (source.isEmpty() && startIndex == 0 && endIndex == 0) {
            return@apply
        }
        source.usePinned { sourcePinned ->
            CC_SHA1_Update(ctx.ptr, sourcePinned.addressOf(startIndex), (endIndex - startIndex).convert())
        }
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        destination.asUByteArray().usePinned { destinationPinned ->
            CC_SHA1_Final(destinationPinned.addressOf(destinationOffset), ctx.ptr)
        }
        reset()
    }

    override fun reset() {
        nativeHeap.free(ctx.ptr)
        ctx = nativeHeap.alloc<CC_SHA1_CTX>().apply {
            CC_SHA1_Init(ptr)
        }
    }
}
