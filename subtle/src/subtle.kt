package io.github.andreypfau.kotlinx.crypto.subtle

@Suppress("NOTHING_TO_INLINE")
public inline fun Int.constantTimeSelect(x: Int, y: Int): Int =
    ((this - 1).inv() and x) or ((this - 1) and y)

@Suppress("NOTHING_TO_INLINE")
public inline fun Int.constantTimeSelect(a: Byte, b: Byte): Byte =
    constantTimeSelect(a.toInt(), b.toInt()).toByte()

@Suppress("NOTHING_TO_INLINE")
public inline fun Int.constantTimeSelect(a: Long, b: Long): Long =
    b xor ((-this).toLong() and (a xor b))

@Suppress("NOTHING_TO_INLINE")
public inline infix fun Byte.constantTimeEquals(y: Byte): Int =
    (((this.toInt() xor y.toInt()).toUInt() - 1u) shr 31).toInt()

@Suppress("NOTHING_TO_INLINE")
public inline infix fun Int.constantTimeEquals(y: Int): Int =
    (((this xor y).toUInt().toULong() - 1u) shr 63).toInt()

public inline fun Int.constantTimeSwap(a: Long, b: Long, block: (Long, Long) -> Unit) {
    val mask = (-this).toLong()
    val t = mask and (a xor b)
    block(a xor t, b xor t)
}

public infix fun ByteArray.constantTimeEquals(other: ByteArray): Int {
    if (size != other.size) return 0
    var v = 0
    for (i in indices) {
        v = v or (this[i].toInt() xor other[i].toInt())
    }
    return v constantTimeEquals 0
}
