package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.enums.CipherAlgorithm
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator

/**
 * TripleDES/ECB 양방향 암호화 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class TripleDESECB : DES() {

    init {
        algorithm = CipherAlgorithm.TRIPLE_DESECB
    }

    override fun generateKey(): Key {
        return try {
            val keyGenerator = KeyGenerator.getInstance("DESede")
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw KeyGenerateException("NoSuchAlgorithmException: \n지원하지 않는 암호화 알고리즘 입니다.")
        }
    }
}
