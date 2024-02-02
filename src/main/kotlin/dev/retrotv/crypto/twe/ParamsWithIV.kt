package dev.retrotv.crypto.twe

class ParamsWithIV(
    override val key: ByteArray,
    val iv: ByteArray
) : Params(key)