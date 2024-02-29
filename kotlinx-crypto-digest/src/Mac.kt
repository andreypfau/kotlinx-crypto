package io.github.andreypfau.kotlinx.crypto

public interface Mac {
    public val algorithmName: String

    public val macSize: Int

    public val blockSize: Int

    public fun update(byte: Byte): Mac

    public fun update(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size): Mac

    public fun doFinal(destination: ByteArray, destinationOffset: Int = 0)

    public fun doFinal(): ByteArray = ByteArray(macSize).apply {
        doFinal(this)
    }

    public fun reset()
}

public inline operator fun Mac.plusAssign(byteArray: ByteArray) {
    update(byteArray)
}
