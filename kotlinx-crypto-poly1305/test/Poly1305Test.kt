package io.github.andreypfau.kotlinx.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals

class Poly1305Test {
    @Test
    fun testNaclVector() {
        val key = "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880".hexToByteArray()
        val msg = ("8e993b9f48681273c29650ba32fc76ce" +
                "48332ea7164d96a4476fb8c531a1186a" +
                "c0dfc17c98dce87b4da7f011ec48c972" +
                "71d2c20f9b928fe2270d6fb863d51738" +
                "b48eeee314a7cc8ab932164548e526ae" +
                "90224368517acfeabd6bb3732bc0e9da" +
                "99832b61ca01b6de56244a9e88d5f9b3" +
                "7973f622a43d14a6599b1f654cb45a74" +
                "e355a5").hexToByteArray()

        val expected = "f3ffc7703f9400e52a7dfb4b3d3305d9".hexToByteArray()

        val result = Poly1305(key).update(msg).doFinal()
        assertContentEquals(expected, result)
    }

    @Test
    fun donnaSelfTest1() {
        // This gives r = 2 and s = 0.
        val key = "0200000000000000000000000000000000000000000000000000000000000000".hexToByteArray()

        // This results in a 130-bit integer with the lower 129 bits all set: m = (1 << 129) - 1
        val msg = "ffffffffffffffffffffffffffffffff".hexToByteArray()

        // The input is a single block, so we should have the following computation:
        //     tag = ((m * r) % p) + s
        //         = ((((1 << 129) - 1) * 2) % p) + 0
        //         = ((1 << 130) - 2) % (1 << 130) - 5
        //         = 3
        val expected = "03000000000000000000000000000000".hexToByteArray()

        val poly = Poly1305(key)
        poly.update(msg)
        assertContentEquals(expected, poly.doFinal())
    }

    @Test
    fun testTlsVectors() {
        val key = "this is 32-byte key for Poly1305".encodeToByteArray()
        val msg = ByteArray(32)
        val expected = "49ec78090e481ec6c26b33b91ccc0307".hexToByteArray()

        val poly = Poly1305(key)
        msg.asSequence().chunked(Poly1305.BLOCK_SIZE_BYTES) {
            it.toByteArray()
        }.forEach {
            poly.update(it)
        }

        assertContentEquals(expected, poly.doFinal())
    }

    // From <https://tools.ietf.org/html/rfc7539#section-2.5.2>
    @Test
    fun testRfc7539Vector() {
        val key = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b".hexToByteArray()
        val msg = "43727970746f6772617068696320466f72756d2052657365617263682047726f7570".hexToByteArray()
        val expected = "a8061dc1305136c6c22b8baf0c0127a9".hexToByteArray()

        val result = Poly1305(key).update(msg).doFinal()
        assertContentEquals(expected, result)
    }
}
