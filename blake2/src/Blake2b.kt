package io.github.andreypfau.kotlinx.crypto

public open class Blake2b(
    digestSize: Int,
    key: ByteArray
) : Digest {
    public constructor() : this(512, EMPTY_BYTES)
    public constructor(key: ByteArray) : this(512, key)
    public constructor(digestSize: Int) : this(digestSize, EMPTY_BYTES)

    final override val digestSize: Int = run {
        require(digestSize in 8..512 && digestSize % 8 == 0) {
            "Invalid digest size: $digestSize"
        }
        digestSize / 8
    }
    override val blockSize: Int get() = BLOCK_SIZE_BYTES
    override val algorithmName: String get() = "BLAKE2b"

    private var fanout = 1
    private var depth = 1
    private var leafLength = 0
    private var nodeOffset = 0L
    private var nodeDepth = 0
    private var innerHashLength = 0

    protected var isLastNode: Boolean = false

    private val buffer = ByteArray(BLOCK_SIZE_BYTES)
    private var bufferPos = 0
    private val internalState = LongArray(16)
    private val chainValue = BLAKE2B_IV.copyOf()

    private var t0 = 0L // holds last significant bits, counter (counts bytes)
    private var t1 = 0L // counter: Length up to 2^128 are supported
    private var f0 = 0L // finalization flag, for last block: ~0L
    private var f1 = 0L // finalization flag, for last node: ~0L

    init {
        var keyLength = 0
        if (key.isNotEmpty()) {
            keyLength = key.size
            key.copyInto(buffer)
            bufferPos = BLOCK_SIZE_BYTES
        }
        chainValue[0] = (BLAKE2B_IV[0]
                xor (this.digestSize.toLong() or (keyLength.toLong() shl 8) or ((fanout.toLong() shl 16) or (depth.toLong() shl 24) or (leafLength.toLong() shl 32))))
        chainValue[1] = BLAKE2B_IV[1] xor nodeOffset
        chainValue[2] = BLAKE2B_IV[2] xor (nodeDepth.toLong() or (innerHashLength.toLong() shl 8))
    }

    override fun update(byte: Byte): Blake2b = apply {
        var remainingLength = BLOCK_SIZE_BYTES - bufferPos
        if (remainingLength == 0) {
            t0 += BLOCK_SIZE_BYTES
            if (t0 == 0L) { // if message > 2^64
                t1++
            }
            compress(buffer, 0)
            buffer.fill(0)
            buffer[0] = byte
            bufferPos = 1
        } else {
            buffer[bufferPos++] = byte
        }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Blake2b = apply {
        val length = endIndex - startIndex
        if (length == 0) {
            return@apply
        }
        var remainingLength = 0
        if (bufferPos != 0) { // commenced, incomplete buffer
            remainingLength = BLOCK_SIZE_BYTES - bufferPos
            if (remainingLength < length) { // full buffer + at least 1 byte
                source.copyInto(buffer, bufferPos, startIndex, startIndex + remainingLength)
                t0 += BLOCK_SIZE_BYTES
                if (t0 == 0L) {
                    t1++
                }
                compress(buffer, 0)
                buffer.fill(0)
                bufferPos = 0
            } else {
                source.copyInto(buffer, bufferPos, startIndex, endIndex)
                bufferPos += length
                return@apply
            }
        }

        // process blocks except last block (also if last block is full)
        var messagePos = startIndex + remainingLength
        val blockWiseLastPos = endIndex - BLOCK_SIZE_BYTES
        while (messagePos < blockWiseLastPos) {
            t0 += BLOCK_SIZE_BYTES
            if (t0 == 0L) {
                t1++
            }
            compress(source, messagePos)
            messagePos += BLOCK_SIZE_BYTES
        }

        // fill the buffer with left bytes, this might be a full block
        source.copyInto(buffer, 0, messagePos, endIndex)
        bufferPos += endIndex - messagePos
    }

    override fun digest(): ByteArray {
        val result = ByteArray(digestSize)
        digest(result)
        return result
    }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        f0 = -1L
        if (isLastNode) {
            f1 = 0xFFFFFFFF
        }
        t0 += bufferPos
        if (bufferPos > 0 && t0 == 0L) {
            t1++
        }
        compress(buffer, 0)
        buffer.fill(0)
        internalState.fill(0)

        val full = digestSize ushr 3
        val partial = digestSize and 7
        for (i in 0 until full) {
            destination.setLongLeAt(destinationOffset + i * 8, chainValue[i])
        }
        if (partial > 0) {
            val bytes = ByteArray(8)
            bytes.setLongLeAt(0, chainValue[full])
            bytes.copyInto(destination, destinationOffset + digestSize - partial, 0, partial)
        }
        chainValue.fill(0)
        reset()
    }

    override fun reset() {
        buffer.fill(0)
        bufferPos = 0
        internalState.fill(0)
        chainValue.fill(0)
        t0 = 0
        t1 = 0
        f0 = 0
        f1 = 0
    }

    private fun compress(message: ByteArray, messagePos: Int) {
        initializeInternalState()
        val m = LongArray(16) { i -> message.getLongLeAt(messagePos + i * 8) }

        for (round in 0 until ROUNDS) {
            // G apply to columns of internalState:m[blake2b_sigma[round][2 * blockPos]] /+1
            g(m[BLAKE2B_SIGMA[round][0].toInt()], m[BLAKE2B_SIGMA[round][1].toInt()], 0, 4, 8, 12);
            g(m[BLAKE2B_SIGMA[round][2].toInt()], m[BLAKE2B_SIGMA[round][3].toInt()], 1, 5, 9, 13);
            g(m[BLAKE2B_SIGMA[round][4].toInt()], m[BLAKE2B_SIGMA[round][5].toInt()], 2, 6, 10, 14);
            g(m[BLAKE2B_SIGMA[round][6].toInt()], m[BLAKE2B_SIGMA[round][7].toInt()], 3, 7, 11, 15);
            // G apply to diagonals of internalState:
            g(m[BLAKE2B_SIGMA[round][8].toInt()], m[BLAKE2B_SIGMA[round][9].toInt()], 0, 5, 10, 15);
            g(m[BLAKE2B_SIGMA[round][10].toInt()], m[BLAKE2B_SIGMA[round][11].toInt()], 1, 6, 11, 12);
            g(m[BLAKE2B_SIGMA[round][12].toInt()], m[BLAKE2B_SIGMA[round][13].toInt()], 2, 7, 8, 13);
            g(m[BLAKE2B_SIGMA[round][14].toInt()], m[BLAKE2B_SIGMA[round][15].toInt()], 3, 4, 9, 14);
        }

        // update chain values:
        for (offset in chainValue.indices) {
            chainValue[offset] = chainValue[offset] xor internalState[offset] xor internalState[offset + 8]
        }
    }

    private fun initializeInternalState() {
        chainValue.copyInto(internalState)
        BLAKE2B_IV.copyInto(internalState, chainValue.size, endIndex = 4)
        internalState[12] = t0 xor BLAKE2B_IV[4]
        internalState[13] = t1 xor BLAKE2B_IV[5]
        internalState[14] = f0 xor BLAKE2B_IV[6]
        internalState[15] = f1 xor BLAKE2B_IV[7]
    }

    private fun g(m1: Long, m2: Long, posA: Int, posB: Int, posC: Int, posD: Int) {
        internalState[posA] = internalState[posA] + internalState[posB] + m1
        internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(32)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] = (internalState[posB] xor internalState[posC]).rotateRight(24) // replaces 25 of BLAKE
        internalState[posA] = internalState[posA] + internalState[posB] + m2
        internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(16)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] = (internalState[posB] xor internalState[posC]).rotateRight(63) // replaces 11 of BLAKE
    }

    public companion object {
        private val EMPTY_BYTES = ByteArray(0)
        private const val ROUNDS = 12 // to use for Catenas H'
        private const val BLOCK_SIZE_BYTES = 128

        private val BLAKE2B_IV = longArrayOf(
            0x6a09e667f3bcc908L, -0x4498517a7b3558c5L, 0x3c6ef372fe94f82bL,
            -0x5ab00ac5a0e2c90fL, 0x510e527fade682d1L, -0x64fa9773d4c193e1L,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
        )
        private val BLAKE2B_SIGMA = arrayOf(
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            byteArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            byteArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            byteArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            byteArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            byteArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            byteArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            byteArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            byteArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
        )

        private fun ByteArray.setLongLeAt(offset: Int, value: Long) {
            this[offset] = value.toByte()
            this[offset + 1] = (value ushr 8).toByte()
            this[offset + 2] = (value ushr 16).toByte()
            this[offset + 3] = (value ushr 24).toByte()
            this[offset + 4] = (value ushr 32).toByte()
            this[offset + 5] = (value ushr 40).toByte()
            this[offset + 6] = (value ushr 48).toByte()
            this[offset + 7] = (value ushr 56).toByte()
        }

        private fun ByteArray.getLongLeAt(offset: Int): Long {
            return (this[offset].toLong() and 0xFF) or
                    ((this[offset + 1].toLong() and 0xFF) shl 8) or
                    ((this[offset + 2].toLong() and 0xFF) shl 16) or
                    ((this[offset + 3].toLong() and 0xFF) shl 24) or
                    ((this[offset + 4].toLong() and 0xFF) shl 32) or
                    ((this[offset + 5].toLong() and 0xFF) shl 40) or
                    ((this[offset + 6].toLong() and 0xFF) shl 48) or
                    ((this[offset + 7].toLong() and 0xFF) shl 56)
        }
    }
}
