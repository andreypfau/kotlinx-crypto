package io.github.andreypfau.kotlinx.crypto.keccak

import io.github.andreypfau.kotlinx.crypto.digest.plusAssign
import kotlin.test.Test
import kotlin.test.assertContentEquals

class SHA3Test {
    @Test
    fun testSha3() {
        assertSha3("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "")
        assertSha3("80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b", "a")
        assertSha3("5c828b33397f4762922e39a60c35699d2550466a52dd15ed44da37eb0bdc61e6", "ab")
        assertSha3("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "abc")
        assertSha3("6f6f129471590d2c91804c812b5750cd44cbdfb7238541c451e1ea2bc0193177", "abcd")
        assertSha3("d716ec61e18904a8f58679b71cb065d4d5db72e0e0c3f155a4feff7add0e58eb", "abcde")
        assertSha3("59890c1d183aa279505750422e6384ccb1499c793872d6f31bb3bcaa4bc9f5a5", "abcdef")
        assertSha3("7d55114476dfc6a2fbeaa10e221a8d0f32fc8f2efb69a6e878f4633366917a62", "abcdefg")
        assertSha3("3e2020725a38a48eb3bbf75767f03a22c6b3f41f459c831309b06433ec649779", "abcdefgh")
        assertSha3("f74eb337992307c22bc59eb43e59583a683f3b93077e7f2472508e8c464d2657", "abcdefghi")
        assertSha3("d97f84d48722153838d4ede4f8ac5f9dea8abce77cd7367b2eb0dc500a36fbb4", "abcdefghij")
        assertSha3(
            "e3b22a5c33f8001b503c54c3c301c86fd18fee24785424e211621a4e7184d883",
            "Discard medicine more than two years old."
        )
        assertSha3(
            "1f024787815858a4498ea92589e4e4ddb573d38707860121b12433414f25be75",
            "He who has a shady past knows that nice guys finish last."
        )
        assertSha3(
            "bab16090e4b6c44a21b20051d947994b1ddd8c6e7852fdb79e682f5fed42c733",
            "I wouldn't marry him with a ten foot pole."
        )
        assertSha3(
            "8266964ae94d45ab67821d810c18c263d92827818b5066b0198e1fc5f65124a1",
            "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"
        )
        assertSha3(
            "86a9fd7ab1d228b1dd452afe8e699d8e4af8bb76115bb0b1abf7e33fcf4f0aba",
            "The days of the digital watch are numbered.  -Tom Stoppard"
        )
        assertSha3("69ecbdaf520318565349f4196b421a58fcab459f30e305b3c178e258289188ac", "Nepal premier won't resign.")
        assertSha3(
            "b35f15904675da9e5f5fc4d445210b837ecc66c227e9cf85054bde3d72890d95",
            "For every action there is an equal and opposite government program."
        )
        assertSha3(
            "9e2df3744ba4a28e68227aea799bef9d02d834cec1dfdbc762012f48c32b0404",
            "His money is twice tainted: 'taint yours and 'taint mine."
        )
        assertSha3(
            "ef8a7d7001f7e9135027e903243707e3d6a92960ba5ad5393fddf669607f2788",
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"
        )
        assertSha3(
            "33b94e962e9fa344a4eea13e7a94da863fa65adb1d299311c3174e379129948f",
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek"
        )
        assertSha3("50fe5ee41a86d50b517bed295bd84fe44712590e3c4f62b971fa512aa3a4f3db", "size:  a.out:  bad magic")
        assertSha3(
            "7f905932d39118e2c89814f3dad5c27cf0df4f21242b9916e7e15cec61bf3e3c",
            "The major problem is with sendmail.  -Mark Horton"
        )
        assertSha3(
            "07fc6febe4075ed5b3855bc28c707fdfef9b5875dc8d2f0f6b4accf0cc0b245f",
            "Give me a rock, paper and scissors and I will move the world.  CCFestoon"
        )
        assertSha3(
            "924e9ef2ded81ed729c9552878c7aadd6beada29e6c4b059df895752893ec16a",
            "If the enemy is within range, then so are you."
        )
        assertSha3(
            "cba17fc956a0b78c1922d350529ef54aa9b9832efa315b025ffa698e72862d26",
            "It's well we cannot hear the screams/That we create in others' dreams."
        )
        assertSha3(
            "a789ec07b1ea22e176d10e80b26adb0d6681682cde21c5c76cb0317ca6ade75a",
            "You remind me of a TV show, but that's all right: I watch it anyway."
        )
        assertSha3(
            "ab8bd93741935e7fb6566d30e087fca28f5e79ce80b6f477fa50ee1fd14d0f0d",
            "C is as portable as Stonehedge!!"
        )
        assertSha3(
            "366420300abeef217f5df49f613d1409e007054f0d62bc57525c2a9afc082adf",
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"
        )
        assertSha3(
            "5b76f64d84aa336381bceea0ed17a27352a3314aee76d133f993760913e23b64",
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"
        )
        assertSha3(
            "e68763c08bc834679e350158a57e3caf2444d9a59b7494b47202dcc4e7f55f41",
            "How can you write a big system without C++?  -Paul Glick"
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun assertSha3(expected: String, input: String) {
        val digest = SHA3()
        digest += input.encodeToByteArray()
        assertContentEquals(expected.hexToByteArray(), digest.digest())
    }
}
