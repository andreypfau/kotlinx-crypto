package io.github.andreypfau.kotlinx.crypto

public infix fun Byte.ctEq(other: Byte): Int {
    return ((this.toInt() xor other.toInt()) - 1) ushr 31
}

public infix fun Int.ctEq(other: Int): Int {
    return (((this xor other).toLong() - 1) ushr 63).toInt()
}

public fun ByteArray.ctCompareTo(other: ByteArray): Int {
    if (this.size != other.size) {
        return 0
    }
    var res = 0
    for (i in this.indices) {
        res = res or (this[i] ctEq other[i])
    }
    return res ctEq 0
}
