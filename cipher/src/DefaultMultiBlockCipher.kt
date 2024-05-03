package io.github.andreypfau.kotlinx.crypto

public abstract class DefaultMultiBlockCipher : MultiBlockCipher {
    override val multiBlockSize: Int
        get() = blockSize

    override fun processBlocks(
        blockCount: Int,
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int
    ): Int {
        var resultLen = 0
        val blockSize = multiBlockSize
        var sourceOffset = startIndex

        for (i in 0 until blockCount) {
            resultLen += encryptBlock(
                source,
                destination,
                destinationOffset + resultLen,
                sourceOffset
            )
            sourceOffset += blockSize
        }

        return resultLen
    }
}
