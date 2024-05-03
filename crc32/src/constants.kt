package io.github.andreypfau.kotlinx.crypto

// IEEE is by far and away the most common CRC-32 polynomial.
// Used by ethernet (IEEE 802.3), v.42, fddi, gzip, zip, png, ...
internal val IEEE_TABLE by lazy(LazyThreadSafetyMode.PUBLICATION) {
    generateCrc32Table(0xEDB88320u)
}

// Castagnoli's polynomial, used in iSCSI.
// Has better error detection characteristics than IEEE.
// https://dx.doi.org/10.1109/26.231911
internal val CASTAGNOLI_TABLE by lazy(LazyThreadSafetyMode.PUBLICATION) {
    generateCrc32Table(0x82F63B78u)
}

private fun generateCrc32Table(poly: UInt): UIntArray {
    val table = UIntArray(256)

    for (idx in table.indices) {
        table[idx] = idx.toUInt()
        for (bit in 8 downTo 1) {
            table[idx] = if (table[idx] % 2U == 0U) {
                table[idx].shr(1)
            } else {
                table[idx].shr(1).xor(poly)
            }
        }
    }

    return table
}
