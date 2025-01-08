package dev.retrotv.crypto.cipher

import dev.retrotv.crypto.cipher.param.Params
import dev.retrotv.crypto.cipher.result.Result

interface TwoWayEncryption {
    fun encrypt(data: ByteArray, params: Params): Result
    fun decrypt(encryptedData: ByteArray, params: Params): Result
}