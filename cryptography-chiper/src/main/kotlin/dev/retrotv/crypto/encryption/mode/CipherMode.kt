package dev.retrotv.crypto.encryption.mode

import dev.retrotv.crypto.encryption.block.BlockCipher
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.result.Result
import dev.retrotv.crypto.enums.EMode

/**
 * 암호화 모드 구현을 위한 추상 클래스 입니다.
 * @param mode 암호화 모드
 * @param blockCipher 블록 암호화 클래스
 */
abstract class CipherMode(val mode: EMode, blockCipher: BlockCipher) {
    val algorithm = blockCipher.algorithm
    protected var engine = blockCipher.engine

    abstract fun encrypt(data: ByteArray, params: Params): Result
    abstract fun decrypt(encryptedData: ByteArray, params: Params): Result
}