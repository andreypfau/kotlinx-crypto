package io.github.andreypfau.kotlinx.crypto.sha2

public actual typealias SHA256 = SHA256Impl

// TODO: use winapi
//@OptIn(ExperimentalNativeApi::class, ExperimentalForeignApi::class)
//public actual class Sha256 : Digest {
//    private val ctx = nativeHeap.alloc<BCRYPT_ALG_HANDLEVar>()
//    private val cleaner = createCleaner(this) {
//        nativeHeap.free(ctx.ptr)
//    }
//
//    override val digestSize: Int get() = 32
//
//    init {
//        BCryptOpenAlgorithmProvider(ctx.ptr, "SHA256", null, 0.convert())
//    }
//
//    override fun write(source: Buffer, byteCount: Long) {
//        TODO("Not yet implemented")
//    }
//
//
//    override fun write(source: ByteArray, startIndex: Int, endIndex: Int) {
//        TODO("Not yet implemented")
//    }
//
//    override fun digest(destination: ByteArray, destinationOffset: Int) {
//        TODO("Not yet implemented")
//    }
//
//    override fun digest(sink: RawSink) {
//        TODO("Not yet implemented")
//    }
//
//    override fun reset() {
//        TODO("Not yet implemented")
//    }
//}
