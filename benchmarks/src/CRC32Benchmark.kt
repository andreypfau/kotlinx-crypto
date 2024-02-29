package io.github.andreypfau.kotlinx.crypto.benchmarks

import io.github.andreypfau.kotlinx.crypto.CRC32Impl
import io.github.andreypfau.kotlinx.crypto.plusAssign
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
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
        val crc32 = CRC32Impl()
        crc32 += byteArray
        return crc32.intDigest()
    }
}
