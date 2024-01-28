package dev.retrotv.crypto.twe.lea

class ParamsWithIV(
    override val key: ByteArray,
    val iv: ByteArray
) : Params(key)