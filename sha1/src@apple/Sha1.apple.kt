package io.github.andreypfau.kotlinx.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

public actual class Sha1 private constructor(
    private val delegate: ССSha1
): Digest by delegate {
    public actual constructor() : this(ССSha1())

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(delegate) {
        it.close()
    }

    actual override fun update(byte: Byte): Sha1 = apply {
        delegate.update(byte)
    }

    actual override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha1 = apply {
        delegate.update(source, startIndex, endIndex)
    }
}

@OptIn(ExperimentalForeignApi::class)
public class ССSha1 : Digest, AutoCloseable {
    override val digestSize: Int get() = CC_SHA1_DIGEST_LENGTH

    override val blockSize: Int get() = CC_SHA1_BLOCK_BYTES

    override val algorithmName: String get() = Sha1Impl.ALGORITHM_NAME

    private var ctx = init()

     override fun update(byte: Byte): ССSha1 = apply {
        memScoped {
            val bytePtr = alloc<ByteVar>()
            bytePtr.value = byte
            CC_SHA1_Update(ctx.ptr, bytePtr.ptr, 1.convert())
        }
    }

     override fun update(source: ByteArray, startIndex: Int, endIndex: Int): ССSha1 = apply {
        if (source.isEmpty() && startIndex == 0 && endIndex == 0) {
            return@apply
        }
        source.usePinned { sourcePinned ->
            CC_SHA1_Update(ctx.ptr, sourcePinned.addressOf(startIndex), (endIndex - startIndex).convert())
        }
    }

    override fun digest(): ByteArray {
        val result = ByteArray(digestSize)
        digest(result)
        return result
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        destination.asUByteArray().usePinned { destinationPinned ->
            CC_SHA1_Final(destinationPinned.addressOf(destinationOffset), ctx.ptr)
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

    private fun init(): CC_SHA1_CTX {
        return nativeHeap.alloc<CC_SHA1_CTX>().apply {
            CC_SHA1_Init(ptr)
        }
    }
}
