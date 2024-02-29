package io.github.andreypfau.kotlinx.crypto

import kotlin.experimental.xor

public fun pbkdf2(
    digest: Digest,
    password: ByteArray,
    salt: ByteArray,
    iterationCount: Int,
    keySize: Int = digest.digestSize
): ByteArray = Pbkdf2(digest, password, salt, iterationCount).deriveKey(keySize)

public class Pbkdf2(
    private val hMac: HMac,
    private val salt: ByteArray,
    private val iterationCount: Int
) {
    public constructor(
        digest: Digest,
        password: ByteArray,
        salt: ByteArray,
        iterationCount: Int
    ) : this(HMac(digest, password), salt, iterationCount)

    private val state = ByteArray(hMac.digestSize)

    public fun deriveKey(keySize: Int = hMac.digestSize): ByteArray {
        val key = ByteArray(keySize)
        deriveKey(key, 0, keySize)
        return key
    }

    public fun deriveKey(destination: ByteArray, destinationOffset: Int = 0, keySize: Int = hMac.digestSize) {
        hMac.reset()

        val digestSize = hMac.digestSize
        val numBlocks = (keySize + digestSize - 1) / digestSize

        val dk = ByteArray(numBlocks * digestSize)
        val buf = ByteArray(4)
        var outPos = destinationOffset

        for (block in 1..numBlocks) {
            buf[0] = (block ushr 24).toByte()
            buf[1] = (block ushr 16).toByte()
            buf[2] = (block ushr 8).toByte()
            buf[3] = block.toByte()

            hMac.update(salt)
            hMac.update(buf)
            hMac.digest(state)
            state.copyInto(dk, outPos)

            for (count in 1 until iterationCount) {
                hMac.update(state)
                hMac.digest(state)
                for (i in state.indices) {
                    dk[outPos + i] = dk[outPos + i] xor state[i]
                }
            }
            outPos += digestSize
        }

        dk.copyInto(destination, destinationOffset, 0, keySize)
    }
}
