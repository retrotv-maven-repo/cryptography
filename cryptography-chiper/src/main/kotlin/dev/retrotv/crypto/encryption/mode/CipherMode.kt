package dev.retrotv.crypto.encryption.mode

import dev.retrotv.crypto.encryption.block.BlockCipher
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.result.Result
import dev.retrotv.crypto.enums.EMode

abstract class CipherMode(val mode: EMode, blockCipher: BlockCipher) {
    val algorithm = blockCipher.algorithm
    protected var engine = blockCipher.engine

    abstract fun encrypt(data: ByteArray, params: Params): Result
    abstract fun decrypt(encryptedData: ByteArray, params: Params): Result
}