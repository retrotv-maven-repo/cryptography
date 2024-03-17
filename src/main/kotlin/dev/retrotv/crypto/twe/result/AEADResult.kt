package dev.retrotv.crypto.twe.result

class AEADResult(
    override val data: ByteArray,
    val tag: ByteArray
) : Result(data)