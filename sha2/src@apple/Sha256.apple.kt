package io.github.andreypfau.kotlinx.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

public actual class Sha256 private constructor(
    private val delegate: CCSha256
) : Digest by delegate {
    public actual constructor() : this(CCSha256())

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(delegate) {
        it.close()
    }

    actual override fun update(byte: Byte): Sha256 {
        delegate.update(byte)
        return this
    }

    actual override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Sha256 {
        delegate.update(source, startIndex, endIndex)
        return this
    }
}

@OptIn(ExperimentalForeignApi::class)
public class CCSha256 : Digest, AutoCloseable {
    override val digestSize: Int get() = CC_SHA256_DIGEST_LENGTH

    override val blockSize: Int get() = CC_SHA256_BLOCK_BYTES

    override val algorithmName: String get() = Sha256Impl.ALGORITHM_NAME

    private var ctx = init()

    override fun update(byte: Byte): CCSha256 = apply {
        memScoped {
            val bytePtr = alloc<ByteVar>()
            bytePtr.value = byte
            CC_SHA256_Update(ctx.ptr, bytePtr.ptr, 1.convert())
        }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): CCSha256 = apply {
        if (source.isEmpty() && startIndex == 0 && endIndex == 0) {
            return@apply
        }
        source.usePinned { sourcePinned ->
            CC_SHA256_Update(ctx.ptr, sourcePinned.addressOf(startIndex), (endIndex - startIndex).convert())
        }
    }

    override fun digest(): ByteArray {
        return ByteArray(CC_SHA256_DIGEST_LENGTH).also { digest(it) }
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        destination.asUByteArray().usePinned { destinationPinned ->
            CC_SHA256_Final(destinationPinned.addressOf(destinationOffset), ctx.ptr)
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

    private fun init(): CC_SHA256_CTX {
        return nativeHeap.alloc<CC_SHA256_CTX>().apply {
            CC_SHA256_Init(ptr)
        }
    }
}
