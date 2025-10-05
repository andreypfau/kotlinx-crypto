package io.github.andreypfau.kotlinx.crypto

// IEEE is by far and away the most common CRC-32 polynomial.
// Used by ethernet (IEEE 802.3), v.42, fddi, gzip, zip, png, ...
internal val IEEE_TABLE_ARRAY = generateCrc32Table(0xEDB88320.toInt())

// Castagnoli's polynomial, used in iSCSI.
// Has better error detection characteristics than IEEE.
// https://dx.doi.org/10.1109/26.231911
internal val CASTAGNOLI_TABLE = generateCrc32Table(0x82F63B78.toInt())

private fun generateCrc32Table(poly: Int): IntArray {
    val table = IntArray(256)

    for (idx in table.indices) {
        table[idx] = idx
        for (bit in 8 downTo 1) {
            table[idx] = if (table[idx] % 2 == 0) {
                table[idx].ushr(1)
            } else {
                table[idx].ushr(1).xor(poly)
            }
        }
    }

    return table
}
