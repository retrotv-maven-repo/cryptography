package dev.retrotv.crypto.encryption.generator

import dev.retrotv.crypto.enums.ECipher
import dev.retrotv.crypto.enums.ECipher.*
import dev.retrotv.crypto.enums.EMode
import dev.retrotv.crypto.enums.EMode.*
import dev.retrotv.crypto.exception.GenerateException
import dev.retrotv.crypto.util.RandomGenerateUtils.generateBytes

object IVGenerator {

    @JvmStatic
    fun generateIV(ivLen: Int): ByteArray {
        require (ivLen in 7..16) { "ivLen의 값은 7 ~ 16 사이의 값이어야 합니다." }
        return generateBytes(ivLen)
    }

    @JvmStatic
    @Throws(GenerateException::class)
    fun generateIV(algorithm: ECipher, mode: EMode): ByteArray {
        return when (mode) {
            ECB -> throw GenerateException("iv가 필요하지 않은 암호화 방식입니다.")
            CBC, CFB, OFB, CTR, CTS ->
                when (algorithm) {
                    AES, ARIA, LEA, SEED, SERPENT -> generateIV(16)
                    DES, TRIPLE_DES -> generateIV(8)
                    else -> throw GenerateException("지원하지 않는 알고리즘 입니다.")
                }
            CCM, GCM ->
                when (algorithm) {
                    AES, ARIA, LEA, SEED, SERPENT, TRIPLE_DES -> generateIV(12)
                    else -> throw GenerateException("지원하지 않는 알고리즘 입니다.")
                }
        }
    }
}
