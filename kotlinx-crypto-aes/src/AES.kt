package io.github.andreypfau.kotlinx.crypto.aes

import io.github.andreypfau.kotlinx.crypto.cipher.DefaultMultiBlockCipher
import io.github.andreypfau.kotlinx.crypto.cipher.MultiBlockCipher

public expect class AES public constructor(key: ByteArray) : MultiBlockCipher

public class AESImpl(
    key: ByteArray
) : DefaultMultiBlockCipher(), MultiBlockCipher {
    override val blockSize: Int get() = BLOCK_SIZE
    override val algorithmName: String get() = "AES"
    private val encryptKey = UIntArray(key.size + 28)
    private val decryptKey = UIntArray(key.size + 28)

    init {
        expandKey(key, encryptKey, decryptKey)
    }

    override fun reset() {
    }

    override fun encryptBlock(
        source: ByteArray, destination: ByteArray, destinationOffset: Int, startIndex: Int
    ): Int {
        val block = uintArrayOf(
            source.getUInt(startIndex + 0),
            source.getUInt(startIndex + 4),
            source.getUInt(startIndex + 8),
            source.getUInt(startIndex + 12)
        )

        encryptBlock(block)

        destination.setUInt(destinationOffset + 0, block[0])
        destination.setUInt(destinationOffset + 4, block[1])
        destination.setUInt(destinationOffset + 8, block[2])
        destination.setUInt(destinationOffset + 12, block[3])

        return BLOCK_SIZE
    }

    override fun decryptBlock(source: ByteArray, destination: ByteArray, destinationOffset: Int, startIndex: Int): Int {
        val block = uintArrayOf(
            source.getUInt(startIndex + 0),
            source.getUInt(startIndex + 4),
            source.getUInt(startIndex + 8),
            source.getUInt(startIndex + 12)
        )

        decryptBlock(block)

        destination.setUInt(destinationOffset + 0, block[0])
        destination.setUInt(destinationOffset + 4, block[1])
        destination.setUInt(destinationOffset + 8, block[2])
        destination.setUInt(destinationOffset + 12, block[3])

        return BLOCK_SIZE
    }

    private fun encryptBlock(
        block: UIntArray
    ) {
        val xk = encryptKey

        // First round just XORs input with key.
        var s0 = block[0] xor xk[0]
        var s1 = block[1] xor xk[1]
        var s2 = block[2] xor xk[2]
        var s3 = block[3] xor xk[3]

        // Middle rounds shuffle using tables.
        // Number of rounds is set by length of expanded key.
        val nr = xk.size / 4 - 2 // - 2: one above, one more below
        var k = 4
        var t0 = 0u
        var t1 = 0u
        var t2 = 0u
        var t3 = 0u
        for (r in 0 until nr) {
            // @formatter:off
            t0 = xk[k + 0] xor te0[(s0 shr 24).toUByte()] xor te1[(s1 shr 16).toUByte()] xor te2[(s2 shr 8).toUByte()] xor te3[s3.toUByte()]
            t1 = xk[k + 1] xor te0[(s1 shr 24).toUByte()] xor te1[(s2 shr 16).toUByte()] xor te2[(s3 shr 8).toUByte()] xor te3[s0.toUByte()]
            t2 = xk[k + 2] xor te0[(s2 shr 24).toUByte()] xor te1[(s3 shr 16).toUByte()] xor te2[(s0 shr 8).toUByte()] xor te3[s1.toUByte()]
            t3 = xk[k + 3] xor te0[(s3 shr 24).toUByte()] xor te1[(s0 shr 16).toUByte()] xor te2[(s1 shr 8).toUByte()] xor te3[s2.toUByte()]
            // @formatter:on
            k += 4
            s0 = t0
            s1 = t1
            s2 = t2
            s3 = t3
        }

        // Last round uses s-box directly and XORs to produce output.
        // @formatter:off
        s0 = (SBOX0[t0 shr 24].toUInt() shl 24) or (SBOX0[t1 shr 16 and 0xFFu].toUInt() shl 16) or (SBOX0[t2 shr 8 and 0xFFu].toUInt() shl 8) or (SBOX0[t3 and 0xFFu].toUInt())
        s1 = (SBOX0[t1 shr 24].toUInt() shl 24) or (SBOX0[t2 shr 16 and 0xFFu].toUInt() shl 16) or (SBOX0[t3 shr 8 and 0xFFu].toUInt() shl 8) or (SBOX0[t0 and 0xFFu].toUInt())
        s2 = (SBOX0[t2 shr 24].toUInt() shl 24) or (SBOX0[t3 shr 16 and 0xFFu].toUInt() shl 16) or (SBOX0[t0 shr 8 and 0xFFu].toUInt() shl 8) or (SBOX0[t1 and 0xFFu].toUInt())
        s3 = (SBOX0[t3 shr 24].toUInt() shl 24) or (SBOX0[t0 shr 16 and 0xFFu].toUInt() shl 16) or (SBOX0[t1 shr 8 and 0xFFu].toUInt() shl 8) or (SBOX0[t2 and 0xFFu].toUInt())
        // @formatter:on

        block[0] = s0 xor xk[k + 0]
        block[1] = s1 xor xk[k + 1]
        block[2] = s2 xor xk[k + 2]
        block[3] = s3 xor xk[k + 3]
    }

    private fun decryptBlock(
        block: UIntArray
    ) {
        val xk = decryptKey

        // First round just XORs input with key.
        var s0 = block[0] xor xk[0]
        var s1 = block[1] xor xk[1]
        var s2 = block[2] xor xk[2]
        var s3 = block[3] xor xk[3]

        // Middle rounds shuffle using tables.
        // Number of rounds is set by length of expanded key.
        val nr = xk.size / 4 - 2 // - 2: one above, one more below
        var k = 4
        var t0 = 0u
        var t1 = 0u
        var t2 = 0u
        var t3 = 0u
        for (r in 0 until nr) {
            // @formatter:off
            t0 = xk[k + 0] xor td0[(s0 shr 24).toUByte()] xor td1[(s3 shr 16).toUByte()] xor td2[(s2 shr 8).toUByte()] xor td3[s1.toUByte()]
            t1 = xk[k + 1] xor td0[(s1 shr 24).toUByte()] xor td1[(s0 shr 16).toUByte()] xor td2[(s3 shr 8).toUByte()] xor td3[s2.toUByte()]
            t2 = xk[k + 2] xor td0[(s2 shr 24).toUByte()] xor td1[(s1 shr 16).toUByte()] xor td2[(s0 shr 8).toUByte()] xor td3[s3.toUByte()]
            t3 = xk[k + 3] xor td0[(s3 shr 24).toUByte()] xor td1[(s2 shr 16).toUByte()] xor td2[(s1 shr 8).toUByte()] xor td3[s0.toUByte()]
            // @formatter:on
            k += 4
            s0 = t0
            s1 = t1
            s2 = t2
            s3 = t3
        }

        // Last round uses s-box directly and XORs to produce output.
        // @formatter:off
        s0 = (SBOX1[t0 shr 24].toUInt() shl 24) or (SBOX1[t3 shr 16 and 0xFFu].toUInt() shl 16) or (SBOX1[t2 shr 8 and 0xFFu].toUInt() shl 8) or (SBOX1[t1 and 0xFFu].toUInt())
        s1 = (SBOX1[t1 shr 24].toUInt() shl 24) or (SBOX1[t0 shr 16 and 0xFFu].toUInt() shl 16) or (SBOX1[t3 shr 8 and 0xFFu].toUInt() shl 8) or (SBOX1[t2 and 0xFFu].toUInt())
        s2 = (SBOX1[t2 shr 24].toUInt() shl 24) or (SBOX1[t1 shr 16 and 0xFFu].toUInt() shl 16) or (SBOX1[t0 shr 8 and 0xFFu].toUInt() shl 8) or (SBOX1[t3 and 0xFFu].toUInt())
        s3 = (SBOX1[t3 shr 24].toUInt() shl 24) or (SBOX1[t2 shr 16 and 0xFFu].toUInt() shl 16) or (SBOX1[t1 shr 8 and 0xFFu].toUInt() shl 8) or (SBOX1[t0 and 0xFFu].toUInt())
        // @formatter:on

        block[0] = s0 xor xk[k + 0]
        block[1] = s1 xor xk[k + 1]
        block[2] = s2 xor xk[k + 2]
        block[3] = s3 xor xk[k + 3]
    }

    private fun expandKey(
        key: ByteArray,
        encrypt: UIntArray,
        decrypt: UIntArray
    ) {
        val nk = key.size / 4
        var i = 0
        while (i < nk) {
            encrypt[i] = key.getUInt(i * 4)
            i++
        }
        while (i < encrypt.size) {
            var t = encrypt[i - 1]
            if (i % nk == 0) {
                t = subw(rotw(t)) xor (POWX[i / nk - 1].toUInt() shl 24)
            } else if (nk > 6 && i % nk == 4) {
                t = subw(t)
            }
            encrypt[i] = encrypt[i - nk] xor t
            i++
        }

        // Derive decryption key from encryption key.
        // Reverse the 4-word round key sets from enc to produce dec.
        // All sets but the first and last get the MixColumn transform applied.
        val n = encrypt.size
        for (k in 0 until n step 4) {
            val ei = n - k - 4
            for (j in 0 until 4) {
                var x = encrypt[ei + j]
                if (k > 0 && k + 4 < n) {
                    x = td0[SBOX0[x shr 24]] xor
                            td1[SBOX0[x shr 16 and 0xFFu]] xor
                            td2[SBOX0[x shr 8 and 0xFFu]] xor
                            td3[SBOX0[x and 0xFFu]]
                }
                decrypt[k + j] = x
            }
        }
    }
}

private const val BLOCK_SIZE = 16

/**
 * Apply [SBOX0] to each byte in [x].
 */
private inline fun subw(x: UInt) =
    (SBOX0[x shr 24].toUInt() shl 24) or
            (SBOX0[x shr 16 and 0xFFu].toUInt() shl 16) or
            (SBOX0[x shr 8 and 0xFFu].toUInt() shl 8) or
            (SBOX0[x and 0xFFu].toUInt())

// Rotate
private inline fun rotw(w: UInt) = (w shl 8) or (w shr 24)

private fun ByteArray.getInt(index: Int): Int =
    ((this[index + 0].toInt() and 0xFF) shl 24) or
            ((this[index + 1].toInt() and 0xFF) shl 16) or
            ((this[index + 2].toInt() and 0xFF) shl 8) or
            (this[index + 3].toInt() and 0xFF)

private inline fun ByteArray.getUInt(index: Int): UInt = getInt(index).toUInt()

private fun ByteArray.setUInt(index: Int, value: UInt) {
    this[index + 0] = (value shr 24).toByte()
    this[index + 1] = (value shr 16).toByte()
    this[index + 2] = (value shr 8).toByte()
    this[index + 3] = value.toByte()
}

private inline operator fun UByteArray.get(index: UInt) = get(index.toInt())
private inline operator fun ByteArray.get(index: UInt) = get(index.toInt())
private inline operator fun UIntArray.get(index: UInt) = get(index.toInt())
private inline operator fun UIntArray.get(index: UByte) = get(index.toInt())
