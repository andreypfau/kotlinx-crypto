package io.github.andreypfau.kotlinx.crypto.sha1

import io.github.andreypfau.kotlinx.crypto.digest.plusAssign
import kotlin.test.Test
import kotlin.test.assertContentEquals

class SHA1Test {
    @Test
    fun testSHA256() {
        assertSha1(
            "76245dbf96f661bd221046197ab8b9f063f11bad",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        )
        assertSha1("da39a3ee5e6b4b0d3255bfef95601890afd80709", "")
        assertSha1("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a")
        assertSha1("da23614e02469a0d7c7bd1bdab5c9c474b1904dc", "ab")
        assertSha1("a9993e364706816aba3e25717850c26c9cd0d89d", "abc")
        assertSha1("81fe8bfe87576c3ecb22426f8e57847382917acf", "abcd")
        assertSha1("03de6c570bfe24bfc328ccd7ca46b76eadaf4334", "abcde")
        assertSha1("1f8ac10f23c5b5bc1167bda84b833e5c057a77d2", "abcdef")
        assertSha1("2fb5e13419fc89246865e7a324f476ec624e8740", "abcdefg")
        assertSha1("425af12a0743502b322e93a015bcf868e324d56a", "abcdefgh")
        assertSha1("c63b19f1e4c8b5f76b25c49b8b87f57d8e4872a1", "abcdefghi")
        assertSha1("d68c19a0a345b7eab78d5e11e991c026ec60db63", "abcdefghij")
        assertSha1("ebf81ddcbe5bf13aaabdc4d65354fdf2044f38a7", "Discard medicine more than two years old.")
        assertSha1(
            "e5dea09392dd886ca63531aaa00571dc07554bb6",
            "He who has a shady past knows that nice guys finish last."
        )
        assertSha1("45988f7234467b94e3e9494434c96ee3609d8f8f", "I wouldn't marry him with a ten foot pole.")
        assertSha1(
            "55dee037eb7460d5a692d1ce11330b260e40c988",
            "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"
        )
        assertSha1(
            "b7bc5fb91080c7de6b582ea281f8a396d7c0aee8",
            "The days of the digital watch are numbered.  -Tom Stoppard"
        )
        assertSha1("c3aed9358f7c77f523afe86135f06b95b3999797", "Nepal premier won't resign.")
        assertSha1(
            "6e29d302bf6e3a5e4305ff318d983197d6906bb9",
            "For every action there is an equal and opposite government program."
        )
        assertSha1(
            "597f6a540010f94c15d71806a99a2c8710e747bd",
            "His money is twice tainted: 'taint yours and 'taint mine."
        )
        assertSha1(
            "6859733b2590a8a091cecf50086febc5ceef1e80",
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"
        )
        assertSha1(
            "514b2630ec089b8aee18795fc0cf1f4860cdacad",
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek"
        )
        assertSha1("c5ca0d4a7b6676fc7aa72caa41cc3d5df567ed69", "size:  a.out:  bad magic")
        assertSha1("74c51fa9a04eadc8c1bbeaa7fc442f834b90a00a", "The major problem is with sendmail.  -Mark Horton")
        assertSha1(
            "0b4c4ce5f52c3ad2821852a8dc00217fa18b8b66",
            "Give me a rock, paper and scissors and I will move the world.  CCFestoon"
        )
        assertSha1("3ae7937dd790315beb0f48330e8642237c61550a", "If the enemy is within range, then so are you.")
        assertSha1(
            "410a2b296df92b9a47412b13281df8f830a9f44b",
            "It's well we cannot hear the screams/That we create in others' dreams."
        )
        assertSha1(
            "841e7c85ca1adcddbdd0187f1289acb5c642f7f5",
            "You remind me of a TV show, but that's all right: I watch it anyway."
        )
        assertSha1("163173b825d03b952601376b25212df66763e1db", "C is as portable as Stonehedge!!")
        assertSha1(
            "32b0377f2687eb88e22106f133c586ab314d5279",
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"
        )
        assertSha1(
            "0885aaf99b569542fd165fa44e322718f4a984e0",
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"
        )
        assertSha1(
            "6627d6904d71420b0bf3886ab629623538689f45",
            "How can you write a big system without C++?  -Paul Glick"
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun assertSha1(expected: String, input: String) {
        assertContentEquals(expected.hexToByteArray(), sha1(input.encodeToByteArray()))

        val pureImpl = SHA1Impl()
        pureImpl += input.encodeToByteArray()
        assertContentEquals(expected.hexToByteArray(), pureImpl.digest())
    }
}
