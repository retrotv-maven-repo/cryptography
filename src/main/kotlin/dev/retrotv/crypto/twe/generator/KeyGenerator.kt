package dev.retrotv.crypto.twe

import dev.retrotv.crypto.exception.GenerateException
import dev.retrotv.enums.Algorithm
import dev.retrotv.enums.Algorithm.Cipher.*
import dev.retrotv.utils.generate

class KeyGenerator {

    fun generateKey(keyLen: Int): ByteArray {
        return generate(keyLen)
    }

    @Throws(GenerateException::class)
    fun generateKey(algorithm: Algorithm.Cipher): ByteArray {
        return when (algorithm) {
            AES, ARIA, LEA -> throw GenerateException("keyLen 인수는 필수 입니다.")
            DES, TRIPLE_DES -> generate(8)
            else -> throw GenerateException("지원하지 않는 알고리즘 입니다.")
        }
    }

    @Throws(GenerateException::class)
    fun generateKey(algorithm: Algorithm.Cipher, keyLen: Int): ByteArray {
        return when (algorithm) {
            AES, ARIA, LEA -> generate(keyLen)
            DES, TRIPLE_DES -> generate(8)
            else -> throw GenerateException("지원하지 않는 알고리즘 입니다.")
        }
    }
}