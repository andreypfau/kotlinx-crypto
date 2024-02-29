package io.github.andreypfau.kotlinx.crypto

/**
 * Base interface for a cipher engine capable of processing multiple blocks at a time.
 */
public interface MultiBlockCipher : BlockCipher {
    /**
     * The multi-block size for this cipher (in bytes).
     */
    public val multiBlockSize: Int

    public fun processBlocks(
        blockCount: Int,
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int = 0,
        startIndex: Int = 0
    ): Int
}
