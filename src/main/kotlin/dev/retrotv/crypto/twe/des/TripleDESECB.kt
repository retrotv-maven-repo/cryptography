package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.enums.CipherAlgorithm
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator

class TripleDESECB : DES() {
    init {
        algorithm = CipherAlgorithm.TRIPLE_DESECB
    }

    @Throws(KeyGenerateException::class)
    override fun generateKey(): Key {
        return try {
            val keyGenerator = KeyGenerator.getInstance("DESede")
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw KeyGenerateException("NoSuchAlgorithmException: \n지원하지 않는 암호화 알고리즘 입니다.")
        }
    }
}
