# Kotlin/Multiplatform Crypto: Poly1305

[Poly1305][1] is a [universal hash function][2] which, when combined with a cipher,
can be used as a [Message Authentication Code (MAC)][3].

In practice, Poly1305 is primarily combined with ciphers from the
[Salsa20 Family][4] such as in `ChaCha20Poly1305` and `XSalsa20Poly1305`
(a.k.a. NaCl `crypto_secretbox`).

[1]: https://en.wikipedia.org/wiki/Poly1305

[2]: https://en.wikipedia.org/wiki/Universal_hashing

[3]: https://en.wikipedia.org/wiki/Message_authentication_code

[4]: https://cr.yp.to/snuffle/salsafamily-20071225.pdf
