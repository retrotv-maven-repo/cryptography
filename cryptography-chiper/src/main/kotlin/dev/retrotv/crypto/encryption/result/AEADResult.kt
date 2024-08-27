package dev.retrotv.crypto.encryption.result

class AEADResult(
    override val data: ByteArray,
    val tag: ByteArray
) : Result(data)