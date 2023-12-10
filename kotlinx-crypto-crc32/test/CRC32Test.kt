package io.github.andreypfau.kotlinx.crypto.crc32

import kotlin.test.Test
import kotlin.test.assertEquals

class CRC32Test {

    @Test
    fun `test CRC32`() {
        // @formatter:off
        testCrc32(0x0, 0x0, "")
        testCrc32(0xe8b7be43, 0xc1d04330, "a")
        testCrc32(0x9e83486d, 0xe2a22936, "ab")
        testCrc32(0x352441c2, 0x364b3fb7, "abc")
        testCrc32(0xed82cd11, 0x92c80a31, "abcd")
        testCrc32(0x8587d865, 0xc450d697, "abcde")
        testCrc32(0x4b8e39ef, 0x53bceff1, "abcdef")
        testCrc32(0x312a6aa6, 0xe627f441, "abcdefg")
        testCrc32(0xaeef2a50, 0xa9421b7, "abcdefgh")
        testCrc32(0x8da988af, 0x2ddc99fc, "abcdefghi")
        testCrc32(0x3981703a, 0xe6599437, "abcdefghij")
        testCrc32(0x6b9cdfe7, 0xb2cc01fe, "Discard medicine more than two years old.")
        testCrc32(0xc90ef73f, 0xe28207f, "He who has a shady past knows that nice guys finish last.")
        testCrc32(0xb902341f, 0xbe93f964, "I wouldn't marry him with a ten foot pole.")
        testCrc32(0x42080e8, 0x9e3be0c3, "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave")
        testCrc32(0x154c6d11, 0xf505ef04, "The days of the digital watch are numbered.  -Tom Stoppard")
        testCrc32(0x4c418325, 0x85d3dc82, "Nepal premier won't resign.")
        testCrc32(0x33955150, 0xc5142380, "For every action there is an equal and opposite government program.")
        testCrc32(0x26216a4b, 0x75eb77dd, "His money is twice tainted: 'taint yours and 'taint mine.")
        testCrc32(0x1abbe45e, 0x91ebe9f7, "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977")
        testCrc32(0xc89a94f7, 0xf0b1168e, "It's a tiny change to the code and not completely disgusting. - Bob Manchek")
        testCrc32(0xab3abe14, 0x572b74e2, "size:  a.out:  bad magic")
        testCrc32(0xbab102b6, 0x8a58a6d5, "The major problem is with sendmail.  -Mark Horton")
        testCrc32(0x999149d7, 0x9c426c50, "Give me a rock, paper and scissors and I will move the world.  CCFestoon")
        testCrc32(0x6d52a33c, 0x735400a4, "If the enemy is within range, then so are you.")
        testCrc32(0x90631e8d, 0xbec49c95, "It's well we cannot hear the screams/That we create in others' dreams.")
        testCrc32(0x78309130, 0xa95a2079, "You remind me of a TV show, but that's all right: I watch it anyway.")
        testCrc32(0x7d0a377f, 0xde2e65c5, "C is as portable as Stonehedge!!")
        testCrc32(0x8c79fd79, 0x297a88ed, "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley")
        testCrc32(0xa20b7167, 0x66ed1d8b, "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule")
        testCrc32(0x8e0bb443, 0xdcded527, "How can you write a big system without C++?  -Paul Glick")
        // @formatter:on
    }

    private fun testCrc32(ieee: Long, castagnoli: Long, input: String) {
        assertEquals(ieee.toInt(), crc32(input.encodeToByteArray()))
        assertEquals(castagnoli.toInt(), crc32c(input.encodeToByteArray()))
    }
}
