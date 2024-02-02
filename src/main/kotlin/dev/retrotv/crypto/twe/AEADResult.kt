package dev.retrotv.crypto.twe

class AEADResult(
    override val data: ByteArray,
    val tag: ByteArray
) : Result(data)