package io.github.andreypfau.kotlinx.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

public actual class Sha512 private constructor(
    private val ccSha512: CCSha512
) : Digest by ccSha512 {
    public actual constructor() : this(CCSha512())

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(ccSha512) {
        it.close()
    }

    actual override fun update(byte: Byte): Sha512 = apply {
        ccSha512.update(byte)
    }

    actual override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha512 = apply {
        ccSha512.update(source, startIndex, endIndex)
    }
}

@OptIn(ExperimentalForeignApi::class)
private class CCSha512 : Digest, AutoCloseable {
    override val digestSize: Int get() = CC_SHA512_DIGEST_LENGTH

    override val blockSize: Int get() = CC_SHA512_BLOCK_BYTES

    override val algorithmName: String get() = Sha512Impl.ALGORITHM_NAME

    private var ctx = init()

    override fun update(byte: Byte) = apply {
        memScoped {
            val bytePtr = alloc<ByteVar>()
            bytePtr.value = byte
            CC_SHA512_Update(ctx.ptr, bytePtr.ptr, 1.convert())
        }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) = apply {
        if (source.isEmpty() && startIndex == 0 && endIndex == 0) {
            return@apply
        }
        source.usePinned { sourcePinned ->
            CC_SHA512_Update(ctx.ptr, sourcePinned.addressOf(startIndex), (endIndex - startIndex).convert())
        }
    }

    override fun digest(): ByteArray {
        return ByteArray(CC_SHA512_DIGEST_LENGTH).also { digest(it) }
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        destination.asUByteArray().usePinned { destinationPinned ->
            CC_SHA512_Final(destinationPinned.addressOf(destinationOffset), ctx.ptr)
        }
        reset()
    }

    override fun reset() {
        close()
        ctx = init()
    }

    override fun close() {
        nativeHeap.free(ctx.ptr)
    }

    private fun init(): CC_SHA512_CTX {
        return nativeHeap.alloc<CC_SHA512_CTX>().apply {
            CC_SHA512_Init(ptr)
        }
    }
}
