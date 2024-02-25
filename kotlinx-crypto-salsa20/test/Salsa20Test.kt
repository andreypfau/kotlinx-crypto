package io.github.andreypfau.kotlinx.crypto.salsa20

import kotlin.test.Test
import kotlin.test.assertContentEquals

class Salsa20Test {
    @Test
    fun salsa20Test() {
        assertSalsa20(
            key = "80000000000000000000000000000000",
            iv = "0000000000000000",
            si = 0,
            expected = "4DFA5E481DA23EA09A31022050859936DA52FCEE218005164F267CB65F5CFD7F2B4F97E0FF16924A52DF269515110A07F9E460BC65EF95DA58F740B7D1DBB0AA"
        )
        assertSalsa20(
            key = "80000000000000000000000000000000",
            iv = "0000000000000000",
            si = 192,
            expected = "DA9C1581F429E0A00F7D67E23B730676783B262E8EB43A25F55FB90B3E753AEF8C6713EC66C51881111593CCB3E8CB8F8DE124080501EEEB389C4BCB6977CF95"
        )
        assertSalsa20(
            key = "80000000000000000000000000000000",
            iv = "0000000000000000",
            si = 256,
            expected = "7D5789631EB4554400E1E025935DFA7B3E9039D61BDC58A8697D36815BF1985CEFDF7AE112E5BB81E37ECF0616CE7147FC08A93A367E08631F23C03B00A8DA2F"
        )
        assertSalsa20(
            key = "80000000000000000000000000000000",
            iv = "0000000000000000",
            si = 448,
            expected = "B375703739DACED4DD4059FD71C3C47FC2F9939670FAD4A46066ADCC6A5645783308B90FFB72BE04A6B147CBE38CC0C3B9267C296A92A7C69873F9F263BE9703"
        )
        // Set 6, vector#  3:
        assertSalsa20(
            key = "0F62B5085BAE0154A7FA4DA0F34699EC",
            iv = "288FF65DC42B92F9",
            si = 0,
            expected = "71DAEE5142D0728B41B6597933EBF467E43279E30978677078941602629CBF68B73D6BD2C95F118D2B3E6EC955DABB6DC61C4143BC9A9B32B99DBE6866166DC0"
        )
        assertSalsa20(
            key = "0F62B5085BAE0154A7FA4DA0F34699EC",
            iv = "288FF65DC42B92F9",
            si = 65472,
            expected = "906258725DDD0323D8E3098CBDAD6B7F941682A4745E4A42B3DC6EDEE565E6D9C65630610CDB14B5F110425F5A6DBF1870856183FA5B91FC177DFA721C5D6BF0"
        )
        assertSalsa20(
            key = "0F62B5085BAE0154A7FA4DA0F34699EC",
            iv = "288FF65DC42B92F9",
            si = 65536,
            expected = "09033D9EBB07648F92858913E220FC528A10125919C891CCF8051153229B958BA9236CADF56A0F328707F7E9D5F76CCBCAF5E46A7BB9675655A426ED377D660E"
        )
        assertSalsa20(
            key = "0F62B5085BAE0154A7FA4DA0F34699EC",
            iv = "288FF65DC42B92F9",
            si = 131008,
            expected = "F9876CA5B5136805445520CDA425508AE0E36DE975DE381F80E77D951D885801CEB354E4F45A2ED5F51DD61CE09942277F493452E0768B2624FACA4D9E0F7BE4"
        )
    }

    private fun assertSalsa20(
        key: String,
        iv: String,
        si: Int,
        expected: String
    ) {
        val salsa20 = Salsa20(key.hexToByteArray(), iv.hexToByteArray())
        val actual = ByteArray(expected.length / 2)
        salsa20.seekTo(si.toLong())
        salsa20.processBytes(ByteArray(actual.size), actual)
        assertContentEquals(expected.hexToByteArray(), actual)
    }
}
