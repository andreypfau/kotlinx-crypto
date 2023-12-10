package io.github.andreypfau.kotlinx.crypto.benchmarks

import io.github.andreypfau.kotlinx.crypto.crc32.CRC32Pure
import io.github.andreypfau.kotlinx.crypto.digest.plusAssign
import kotlinx.benchmark.*
import kotlin.random.Random

@State(Scope.Benchmark)
open class CRC32Benchmark {
    private lateinit var byteArray: ByteArray

    @Setup
    fun fillByteArray() {
        byteArray = Random.nextBytes(1024)
    }

    @Benchmark
    fun benchmarkPure(): Int {
        val crc32 = CRC32Pure()
        crc32 += byteArray
        return crc32.intDigest()
    }
}
