package dev.retrotv.crypto.owe.password.pbkdf2

import dev.retrotv.crypto.owe.password.KDF
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm

/**
 * Pbkdf2 알고리즘으로 암호화 하기 위한 [KDF] 추상 클래스의 구현체 입니다.
 * Spring Security의 [PasswordEncoder]와 호환됩니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class Pbkdf2 : KDF {
    private val pbkdf2PasswordEncoder: Pbkdf2PasswordEncoder

    constructor() {
        pbkdf2PasswordEncoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()
    }

    constructor(
        secret: CharSequence?, saltLength: Int, iterations: Int,
        secretKeyFactoryAlgorithm: SecretKeyFactoryAlgorithm?
    ) {
        pbkdf2PasswordEncoder = Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm)
    }

    override fun encode(rawPassword: CharSequence): String {
        return pbkdf2PasswordEncoder.encode(rawPassword)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else pbkdf2PasswordEncoder.matches(rawPassword, encodedPassword)
    }
}
