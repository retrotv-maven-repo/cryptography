package dev.retrotv.crypto.twe

import dev.retrotv.crypto.exception.GenerateException
import dev.retrotv.enums.Algorithm.Cipher
import dev.retrotv.enums.Algorithm.Cipher.*
import dev.retrotv.enums.Mode
import dev.retrotv.enums.Mode.*
import dev.retrotv.utils.generate

class IVGenerator {

    fun generateIV(ivLen: Int): ByteArray {
        return generate(ivLen)
    }

    @Throws(GenerateException::class)
    fun generateIV(algorithm: Cipher, mode: Mode): ByteArray {
        return when (mode) {
            ECB -> throw GenerateException("iv가 필요하지 않은 암호화 방식입니다.")
            CBC, CFB, OFB, CTR, CTS ->
                when (algorithm) {
                    AES, ARIA, LEA -> generateIV(16)
                    DES, TRIPLE_DES -> generateIV(8)
                    else -> throw GenerateException("지원하지 않는 알고리즘 입니다.")
                }
            CCM, GCM ->
                when (algorithm) {
                    AES, ARIA, LEA -> generateIV(12)
                    else -> throw GenerateException("지원하지 않는 알고리즘 입니다.")
                }
        }
    }
}