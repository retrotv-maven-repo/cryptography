package dev.retrotv.crypto.encryption.param

class ParamsWithIV(
    override val key: ByteArray,
    val iv: ByteArray?
) : Params(key)