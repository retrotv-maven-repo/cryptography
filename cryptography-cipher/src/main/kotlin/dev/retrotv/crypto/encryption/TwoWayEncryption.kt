package dev.retrotv.crypto.encryption

import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.result.Result

interface TwoWayEncryption {
    fun encrypt(data: ByteArray, params: Params): Result
    fun decrypt(encryptedData: ByteArray, params: Params): Result
}