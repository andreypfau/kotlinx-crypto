package io.github.andreypfau.kotlinx.crypto.keccak

import io.github.andreypfau.kotlinx.crypto.digest.plusAssign
import kotlin.test.Test
import kotlin.test.assertContentEquals

class KeccakTest {
    @Test
    fun testKeccak() {
        assertKeccak("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "")
        assertKeccak("3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb", "a")
        assertKeccak("67fad3bfa1e0321bd021ca805ce14876e50acac8ca8532eda8cbf924da565160", "ab")
        assertKeccak("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "abc")
        assertKeccak("48bed44d1bcd124a28c27f343a817e5f5243190d3c52bf347daf876de1dbbf77", "abcd")
        assertKeccak("6377c7e66081cb65e473c1b95db5195a27d04a7108b468890224bedbe1a8a6eb", "abcde")
        assertKeccak("acd0c377fe36d5b209125185bc3ac41155ed1bf7103ef9f0c2aff4320460b6df", "abcdef")
        assertKeccak("a82aec019867b7307551dc397acde18b541e742fa1a4e53df4ce3b02d462f524", "abcdefg")
        assertKeccak("48624fa43c68d5c552855a4e2919e74645f683f5384f72b5b051b71ea41d4f2d", "abcdefgh")
        assertKeccak("34fb2702da7001bf4dbf26a1e4cf31044bd95b85e1017596ee2d23aedc90498b", "abcdefghi")
        assertKeccak("f8da54b5a7dd75028acb077ee61e8dde47ed37c746703ce764edf4a789eb2103", "abcdefghij")
        assertKeccak(
            "f02f7bafef53c09bd71f5d0a22c267a1b01a543aa5f4be05f0d88ea683a37266",
            "Discard medicine more than two years old."
        )
        assertKeccak(
            "3719a0b0b1e95b14dd0274fcd2eb8ac3cb0b9af8c032b767821b3fef036d2717",
            "He who has a shady past knows that nice guys finish last."
        )
        assertKeccak(
            "f1ef9acd04c321aa8122bb8c5cf812776dcfa33e18fbb0cc52c6c6f35f2757a8",
            "I wouldn't marry him with a ten foot pole."
        )
        assertKeccak(
            "35edd2014775f9fe8da3f8567a478f39daa861c1350ddedb2f61e05b733a976d",
            "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"
        )
        assertKeccak(
            "f3e52fda127a4fe928d125559124b806b83d5f843a9f999a23f0cfb9fc515b39",
            "The days of the digital watch are numbered.  -Tom Stoppard"
        )
        assertKeccak("0f39c9f917bf8536fb109557db30179d6226e510d4abd9a74ca99ae1a2ad752b", "Nepal premier won't resign.")
        assertKeccak(
            "7d335a1aa35a4ac3ae7ea4992f600859c20360f6b056344b1837d53ad5fa45b0",
            "For every action there is an equal and opposite government program."
        )
        assertKeccak(
            "1aca6f37f0482f98a41a758455f48ec5fdc979c9bec3aeafebc8137ed36871ea",
            "His money is twice tainted: 'taint yours and 'taint mine."
        )
        assertKeccak(
            "97eafbd4d117620989ccd6a125cd59077e214033fa34639bff0bada4967bb9c6",
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"
        )
        assertKeccak(
            "b223e44f2a28d78fa8a98b29f84457600c64f0426bbee27e53745c775a448d67",
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek"
        )
        assertKeccak("102ef8cde52813c1bd531729f64706209b06c06debab4bbe68c00b47e9c4faeb", "size:  a.out:  bad magic")
        assertKeccak(
            "2ad8ce486b4bdf78b0cd69b6275cab1aea91d338da3a88c2e7285794ae82fef6",
            "The major problem is with sendmail.  -Mark Horton"
        )
        assertKeccak(
            "d8d4dd4bd56961d9f7d0587a8dd1538ff8da3682997a3b00101f81538de2598c",
            "Give me a rock, paper and scissors and I will move the world.  CCFestoon"
        )
        assertKeccak(
            "ae7e9bc6208622e7ec9e4a33587c448b3bed80d7dfea9689f6c2b150f24be21e",
            "If the enemy is within range, then so are you."
        )
        assertKeccak(
            "a3a4926a0efe719e818a336253bfbc8751fbd1ca6affcdad57d48ba928af6f1d",
            "It's well we cannot hear the screams/That we create in others' dreams."
        )
        assertKeccak(
            "8139c3fe5fd03dfbbaf03cba4c2849ebd72907d3d8f5d69cec94a5bf119c98c4",
            "You remind me of a TV show, but that's all right: I watch it anyway."
        )
        assertKeccak(
            "6aed27f23f905b041ce678357b6719515e050e6b991320e7de2099b1afd3e1c8",
            "C is as portable as Stonehedge!!"
        )
        assertKeccak(
            "db5196399f418fac315f6339c482abb0390ea56616d5e3bc643621b60e194753",
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"
        )
        assertKeccak(
            "0a2b2e10ffb7ddd78e025a7bbe28fdfc320c76ad7dbc8c429217e2b5cde8577c",
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"
        )
        assertKeccak(
            "231c9e570dc845439f968b2db1d89cf33c0128d36c0342e93fad2817f53a8ac4",
            "How can you write a big system without C++?  -Paul Glick"
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun assertKeccak(expected: String, input: String) {
        val digest = Keccak()
        digest += input.encodeToByteArray()
        assertContentEquals(expected.hexToByteArray(), digest.digest())
    }
}
