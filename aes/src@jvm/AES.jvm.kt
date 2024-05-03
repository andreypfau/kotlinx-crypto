package io.github.andreypfau.kotlinx.crypto

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

public actual class AES actual constructor(key: ByteArray) : DefaultMultiBlockCipher(), MultiBlockCipher {
    actual override val blockSize: Int get() = 16
    actual override val algorithmName: String get() = "AES"

    private val encryptCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
    }

    private val decryptCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
        init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
    }

    actual override fun encryptBlock(source: ByteArray, destination: ByteArray, destinationOffset: Int, startIndex: Int): Int {
        return encryptCipher.doFinal(source, startIndex, blockSize, destination, destinationOffset)
    }

    actual override fun decryptBlock(source: ByteArray, destination: ByteArray, destinationOffset: Int, startIndex: Int): Int {
        return decryptCipher.doFinal(source, startIndex, blockSize, destination, destinationOffset)
    }

    actual override fun reset() {
    }
}
