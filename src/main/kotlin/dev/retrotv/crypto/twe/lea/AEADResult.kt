package dev.retrotv.crypto.twe.lea

class AEADResult(
    override val data: ByteArray,
    val tag: ByteArray
) : Result(data) {
}