@file:JvmName("KeyGenerator")
package dev.retrotv.crypto.twe.generator

import dev.retrotv.crypto.exception.GenerateException
import dev.retrotv.enums.Algorithm
import dev.retrotv.enums.Algorithm.Cipher.*
import dev.retrotv.utils.generate

fun generateKey(keyLen: Int): ByteArray {
    require (keyLen == 8 || keyLen == 16 || keyLen == 24 || keyLen == 32) {
        "keyLen의 값은 8, 16, 24, 32 중 하나의 값이어야 합니다."
    }

    return generate(keyLen)
}

@JvmOverloads
@Throws(GenerateException::class)
fun generateKey(algorithm: Algorithm.Cipher, keyLen: Int? = null): ByteArray {
    return when (algorithm) {
        AES, ARIA, LEA -> {
            if (keyLen == null) {
                throw GenerateException("keyLen 인수는 필수 입니다.")
            } else {
                generateKey(keyLen)
            }
        }
        DES, TRIPLE_DES -> generateKey(8)
        else -> throw GenerateException("지원하지 않는 알고리즘 입니다.")
    }
}