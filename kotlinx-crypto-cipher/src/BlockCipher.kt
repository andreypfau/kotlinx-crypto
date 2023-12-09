package io.github.andreypfau.kotlinx.crypto.cipher

/**
 * Block cipher engines are expected to conform to this interface.
 */
public interface BlockCipher {
    /**
     * The block size for this cipher (in bytes).
     */
    public val blockSize: Int

    public val algorithmName: String

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     */
    public fun encryptBlock(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int = 0,
        startIndex: Int = 0,
    ): Int

    public fun decryptBlock(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int = 0,
        startIndex: Int = 0,
    ): Int

    /**
     * Reset the cipher. After resetting, the cipher is in the same state
     * as it was after the last initialization (if there was one).
     */
    public fun reset()
}
