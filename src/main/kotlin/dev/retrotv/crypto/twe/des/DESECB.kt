package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.enums.Algorithm
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator

/**
 * DES/ECB 양방향 암호화 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다.")
class DESECB : DES() {

    init {
        algorithm = Algorithm.Cipher.DESECB
    }
}
