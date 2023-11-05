package dev.retrotv.utils

import java.security.SecureRandom

class SecureRandomUtil private constructor() {
    init {
        throw IllegalStateException("유틸리티 클래스 입니다.")
    }

    companion object {
        fun generate(len: Int): ByteArray {
            val sr = SecureRandom()
            val randomData = ByteArray(len)
            sr.nextBytes(randomData)
            return randomData
        }
    }
}
