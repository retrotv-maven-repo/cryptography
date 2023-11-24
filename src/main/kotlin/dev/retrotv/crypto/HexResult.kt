package dev.retrotv.crypto

import dev.retrotv.data.utils.binaryToHex

class HexResult(data: ByteArray) : EncodeResult(data) {

    init {
        this.data = data
        this.encodedData = binaryToHex(data)
    }

    fun getData(): ByteArray = this.data

    fun getEncodedData(): String = this.encodedData
}