package dev.retrotv.crypto.owe.kdf

import org.springframework.security.crypto.password.PasswordEncoder

/**
 * 패스워드 암호화 클래스 구현을 위한 추상 클래스입니다.
 * [PasswordEncoder]를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
abstract class KDF : PasswordEncoder {
    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else encodedPassword == encode(rawPassword)
    }
}
