package dev.retrotv.crypto.twe.param

class ParamsWithIV(
    override val key: ByteArray,
    val iv: ByteArray
) : Params(key)