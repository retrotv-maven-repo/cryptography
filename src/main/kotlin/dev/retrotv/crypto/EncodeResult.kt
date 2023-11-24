package dev.retrotv.crypto

abstract class EncodeResult(data: ByteArray) {
    protected lateinit var data: ByteArray
    protected lateinit var encodedData: String
}