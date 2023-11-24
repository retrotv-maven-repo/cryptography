package dev.retrotv.crypto

import dev.retrotv.data.utils.binaryToBase64

class Base64Result(data: ByteArray) : EncodeResult(data) {

    init {
        this.data = data
        this.encodedData = binaryToBase64(data)
    }

    fun getData(): ByteArray = this.data

    fun getEncodedData(): String = this.encodedData
}