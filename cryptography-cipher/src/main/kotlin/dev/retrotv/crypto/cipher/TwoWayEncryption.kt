package dev.retrotv.crypto.cipher

import dev.retrotv.crypto.cipher.param.Param
import dev.retrotv.crypto.cipher.result.Result

interface TwoWayEncryption {
    fun encrypt(data: ByteArray, params: Param): Result
    fun decrypt(encryptedData: ByteArray, params: Param): Result
}