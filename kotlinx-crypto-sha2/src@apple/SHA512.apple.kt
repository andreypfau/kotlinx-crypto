package io.github.andreypfau.kotlinx.crypto.sha2

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

@OptIn(ExperimentalForeignApi::class)
public actual class SHA512 : Digest {
    override val digestSize: Int get() = CC_SHA512_DIGEST_LENGTH

    override val blockSize: Int get() = CC_SHA512_BLOCK_BYTES

    override val algorithmName: String get() = SHA512Impl.ALGORITHM_NAME

    private var ctx = nativeHeap.alloc<CC_SHA512_CTX>().apply {
        CC_SHA512_Init(ptr)
    }

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(this) {
        nativeHeap.free(ctx.ptr)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
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
        reset()
    }

    override fun reset() {
        nativeHeap.free(ctx.ptr)
        ctx = nativeHeap.alloc<CC_SHA512_CTX>().apply {
            CC_SHA512_Init(ptr)
        }
    }
}
