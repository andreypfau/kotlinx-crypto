import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.hmac.HMac
import io.github.andreypfau.kotlinx.crypto.sha1.SHA1
import io.github.andreypfau.kotlinx.crypto.sha2.SHA256
import io.github.andreypfau.kotlinx.crypto.sha2.SHA512
import kotlin.test.Test
import kotlin.test.assertEquals

class HMacTest {

    // Tests from US FIPS 198
    // https://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf
    @Test
    fun testHMacUsFips198() {
        assertHmac(
            digest = ::SHA1,
            key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".hexToByteArray(),
            input = "Sample #1".encodeToByteArray(),
            output = "4f4ca3d5d68ba7cc0a1208c9c61e9c5da0403c0a".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA1,
            key = "303132333435363738393a3b3c3d3e3f40414243".hexToByteArray(),
            input = "Sample #2".encodeToByteArray(),
            output = "0922d3405faa3d194f82a45830737d5cc6c75d24".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA1,
            key = "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3".hexToByteArray(),
            input = "Sample #3".encodeToByteArray(),
            output = "bcf41eab8bb2d802f3d05caf7cb092ecf8d1a3aa".hexToByteArray()
        )
    }

    @Test
    fun testHmacWithoutKey() {
        assertHmac(
            digest = ::SHA1,
            key = ByteArray(0),
            input = "message".encodeToByteArray(),
            output = "d5d1ed05121417247616cfc8378f360a39da7cfa".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA256,
            key = ByteArray(0),
            input = "message".encodeToByteArray(),
            output = "eb08c1f56d5ddee07f7bdf80468083da06b64cf4fac64fe3a90883df5feacae4".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA512,
            key = ByteArray(0),
            input = "message".encodeToByteArray(),
            output = "08fce52f6395d59c2a3fb8abb281d74ad6f112b9a9c787bcea290d94dadbc82b2ca3e5e12bf2277c7fedbb0154d5493e41bb7459f63c8e39554ea3651b812492".hexToByteArray()
        )
    }

    // Tests from RFC 4231
    @Test
    fun testHMacRfc4231() {
        assertHmac(
            digest = ::SHA256,
            key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".hexToByteArray(),
            input = "Hi There".encodeToByteArray(),
            output = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA256,
            key = "Jefe".encodeToByteArray(),
            input = "what do ya want for nothing?".encodeToByteArray(),
            output = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA256,
            key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".hexToByteArray(),
            input = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".hexToByteArray(),
            output = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA256,
            key = "0102030405060708090a0b0c0d0e0f10111213141516171819".hexToByteArray(),
            input = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".hexToByteArray(),
            output = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA256,
            key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".hexToByteArray(),
            input = "Test Using Larger Than Block-Size Key - Hash Key First".encodeToByteArray(),
            output = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54".hexToByteArray()
        )
        assertHmac(
            digest = ::SHA256,
            key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".hexToByteArray(),
            input = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".encodeToByteArray(),
            output = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2".hexToByteArray()
        )
    }

    private fun assertHmac(
        digest: () -> Digest,
        key: ByteArray,
        input: ByteArray,
        output: ByteArray
    ) {
        HMac(digest(), key).apply {
            update(input)
            val result = ByteArray(digestSize)
            digest(result)
            assertEquals(output.toHexString(), result.toHexString())
        }
    }
}
