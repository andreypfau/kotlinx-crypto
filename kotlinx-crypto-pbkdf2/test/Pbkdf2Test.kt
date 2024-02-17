package io.github.andreypfau.kotlinx.crypto.pbkdf2

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.sha1.SHA1
import io.github.andreypfau.kotlinx.crypto.sha2.SHA256
import kotlin.test.Test
import kotlin.test.assertEquals

class Pbkdf2Test {
    @Test
    fun testPbkdf2Sha1() {
        assertPbkdf2(
            digest = ::SHA1,
            password = "password",
            salt = "salt",
            iterations = 1,
            output = "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        )
        assertPbkdf2(
            digest = ::SHA1,
            password = "password",
            salt = "salt",
            iterations = 2,
            output = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        )
        assertPbkdf2(
            digest = ::SHA1,
            password = "password",
            salt = "salt",
            iterations = 4096,
            output = "4b007901b765489abead49d926f721d065a429c1"
        )
        assertPbkdf2(
            digest = ::SHA1,
            password = "passwordPASSWORDpassword",
            salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            iterations = 4096,
            output = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
        )
        assertPbkdf2(
            digest = ::SHA1,
            password = "pass\u0000word",
            salt = "sa\u0000lt",
            iterations = 4096,
            output = "56fa6aa75548099dcc37d7f03425e0c3"
        )
    }

    @Test
    fun testPbkdf2Sha512() {
        assertPbkdf2(
            digest = ::SHA256,
            password = "password",
            salt = "salt",
            iterations = 1,
            output = "120fb6cffcf8b32c43e7225256c4f837a86548c9"
        )
        assertPbkdf2(
            digest = ::SHA256,
            password = "password",
            salt = "salt",
            iterations = 2,
            output = "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"
        )
        assertPbkdf2(
            digest = ::SHA256,
            password = "password",
            salt = "salt",
            iterations = 4096,
            output = "c5e478d59288c841aa530db6845c4c8d962893a0"
        )
        assertPbkdf2(
            digest = ::SHA256,
            password = "passwordPASSWORDpassword",
            salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            iterations = 4096,
            output = "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c"
        )
        assertPbkdf2(
            digest = ::SHA256,
            password = "pass\u0000word",
            salt = "sa\u0000lt",
            iterations = 4096,
            output = "89b69d0516f829893c696226650a8687"
        )
    }

    private fun assertPbkdf2(
        digest: () -> Digest,
        password: String,
        salt: String,
        iterations: Int,
        output: String
    ) {
        val outputBytes = output.hexToByteArray()
        val result = pbkdf2(
            digest = digest(),
            password = password.encodeToByteArray(),
            salt = salt.encodeToByteArray(),
            iterationCount = iterations,
            keySize = outputBytes.size
        )
        assertEquals(output.lowercase(), result.toHexString())
    }
}
