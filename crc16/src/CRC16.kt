package io.github.andreypfau.kotlinx.crypto

public sealed class CRC16(
    poly: UShort,
    private val init: UShort,
    private val refIn: Boolean,
    private val refOut: Boolean,
    private val xorOut: UShort,
    public override val algorithmName: String
) : ShortDigest {
    override val digestSize: Int get() = Short.SIZE_BYTES
    private var crc: UShort = init

    private val table: UShortArray = generateTable(poly, refIn)

    override fun update(byte: Byte): CRC16 {
        val b = if (refIn) REVERSE_8[byte.toInt() and 0xFF].toInt() else byte.toInt() and 0xFF

        crc = if (refIn) {
            val i = (crc.toInt() xor b) and 0xFF
            ((crc.toInt() shr 8) xor table[i].toInt()).toUShort()
        } else {
            val i = ((crc.toInt() shr 8) xor b) and 0xFF
            ((crc.toInt() shl 8) xor table[i].toInt()).toUShort()
        }
        return this
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int): CRC16 {
        for (i in startIndex until endIndex) update(source[i])
        return this
    }

    override fun digest(): ByteArray = ByteArray(digestSize).also { digest(it, 0) }

    override fun digest(destination: ByteArray, destinationOffset: Int) {
        val xorApplied = (crc xor xorOut)
        val final = if (refOut) reverse16(xorApplied).toInt() else xorApplied.toInt()
        destination[destinationOffset] = (final shr 8).toByte()
        destination[destinationOffset + 1] = (final and 0xFF).toByte()
    }

    override fun shortDigest(): Short {
        val final = if (refOut) reverse16(crc) else crc
        return (final xor xorOut).toShort()
    }

    override fun reset() {
        crc = init
    }

    public companion object {
        public class ARC : CRC16(0x8005u, 0x0000u, true, true, 0x0000u, "CRC-16/ARC")
        public class AUG_CCITT : CRC16(0x1021u, 0x1D0Fu, false, false, 0x0000u, "CRC-16/AUG-CCITT")
        public class BUYPASS : CRC16(0x8005u, 0x0000u, false, false, 0x0000u, "CRC-16/BUYPASS")
        public class CCITT_FALSE : CRC16(0x1021u, 0xFFFFu, false, false, 0x0000u, "CRC-16/CCITT-FALSE")
        public class CDMA2000 : CRC16(0xC867u, 0xFFFFu, false, false, 0x0000u, "CRC-16/CDMA2000")
        public class DDS_110 : CRC16(0x8005u, 0x800Du, false, false, 0x0000u, "CRC-16/DDS-110")
        public class DECT_R : CRC16(0x0589u, 0x0000u, false, false, 0x0001u, "CRC-16/DECT-R")
        public class DECT_X : CRC16(0x0589u, 0x0000u, false, false, 0x0000u, "CRC-16/DECT-X")
        public class DNP : CRC16(0x3D65u, 0x0000u, true, true, 0xFFFFu, "CRC-16/DNP")
        public class EN_13757 : CRC16(0x3D65u, 0x0000u, false, false, 0xFFFFu, "CRC-16/EN-13757")
        public class GENIBUS : CRC16(0x1021u, 0xFFFFu, false, false, 0xFFFFu, "CRC-16/GENIBUS")
        public class MAXIM : CRC16(0x8005u, 0x0000u, true, true, 0xFFFFu, "CRC-16/MAXIM")
        public class MCRF4XX : CRC16(0x1021u, 0xFFFFu, true, true, 0x0000u, "CRC-16/MCRF4XX")
        public class RIELLO : CRC16(0x1021u, 0xB2AAu, true, true, 0x0000u, "CRC-16/RIELLO")
        public class T10_DIF : CRC16(0x8BB7u, 0x0000u, false, false, 0x0000u, "CRC-16/T10-DIF")
        public class TELEDISK : CRC16(0xA097u, 0x0000u, false, false, 0x0000u, "CRC-16/TELEDISK")
        public class TMS37157 : CRC16(0x1021u, 0x89ECu, true, true, 0x0000u, "CRC-16/TMS37157")
        public class USB : CRC16(0x8005u, 0xFFFFu, true, true, 0xFFFFu, "CRC-16/USB")
        public class CRC_A : CRC16(0x1021u, 0xC6C6u, true, true, 0x0000u, "CRC-16/CRC-A")
        public class KERMIT : CRC16(0x1021u, 0x0000u, true, true, 0x0000u, "CRC-16/KERMIT")
        public class MODBUS : CRC16(0x8005u, 0xFFFFu, true, true, 0x0000u, "CRC-16/MODBUS")
        public class X_25 : CRC16(0x1021u, 0xFFFFu, true, true, 0xFFFFu, "CRC-16/X-25")
        public class XMODEM : CRC16(0x1021u, 0x0000u, false, false, 0x0000u, "CRC-16/XMODEM")

        private val REVERSE_8: UByteArray = UByteArray(256) { i ->
            val x = i.toULong()
            val v = (x * 0x0202020202uL and 0x010884422010uL).toInt()
            (v % 1023).toUByte()
        }

        private fun reverse16(x: UShort): UShort {
            val lo = REVERSE_8[x.toInt() and 0xFF].toInt()
            val hi = REVERSE_8[x.toInt() shr 8].toInt()
            return ((lo shl 8) or hi).toUShort()
        }

        public fun generateTable(poly: UShort, refIn: Boolean): UShortArray {
            return UShortArray(256) { n ->
                var crc = if (refIn) {
                    REVERSE_8[n].toInt()
                } else {
                    n shl 8
                }
                repeat(8) {
                    crc = if ((crc and 0x8000) != 0) {
                        (crc shl 1) xor poly.toInt()
                    } else crc shl 1
                }
                if (refIn) reverse16(crc.toUShort()) else crc.toUShort()
            }
        }
    }
}
