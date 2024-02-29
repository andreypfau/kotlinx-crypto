package io.github.andreypfau.kotlinx.crypto

public interface Mac : Digest {
    public override val algorithmName: String

    public val macSize: Int

    override val digestSize: Int
        get() = macSize

    public override val blockSize: Int

    public override fun update(byte: Byte): Mac

    public override fun update(source: ByteArray, startIndex: Int, endIndex: Int): Mac

    public override fun digest(destination: ByteArray, destinationOffset: Int)

    public override fun digest(): ByteArray = ByteArray(macSize).apply {
        digest(this)
    }

    public override fun reset()
}

public inline operator fun Mac.plusAssign(byteArray: ByteArray) {
    update(byteArray)
}
