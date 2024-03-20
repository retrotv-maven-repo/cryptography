package dev.retrotv.crypto.owe.password.bcrypt

import dev.retrotv.crypto.owe.password.KDF
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion
import org.springframework.security.crypto.password.PasswordEncoder
import java.security.SecureRandom

/**
 * BCrypt 알고리즘으로 암호화 하기 위한 [KDF] 추상 클래스의 구현체 입니다.
 * Spring Security의 [PasswordEncoder]와 호환됩니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class BCrypt : KDF {
    private val bCryptPasswordEncoder: BCryptPasswordEncoder

    constructor() {
        bCryptPasswordEncoder = BCryptPasswordEncoder()
    }

    constructor(strength: Int) {
        bCryptPasswordEncoder = BCryptPasswordEncoder(strength)
    }

    constructor(version: BCryptVersion) {
        bCryptPasswordEncoder = BCryptPasswordEncoder(version)
    }

    constructor(version: BCryptVersion, random: SecureRandom) {
        bCryptPasswordEncoder = BCryptPasswordEncoder(version, random)
    }

    constructor(strength: Int, random: SecureRandom) {
        bCryptPasswordEncoder = BCryptPasswordEncoder(strength, random)
    }

    constructor(version: BCryptVersion, strength: Int) {
        bCryptPasswordEncoder = BCryptPasswordEncoder(version, strength)
    }

    constructor(version: BCryptVersion, strength: Int, random: SecureRandom) {
        bCryptPasswordEncoder = BCryptPasswordEncoder(version, strength, random)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else bCryptPasswordEncoder.matches(rawPassword, encodedPassword)
    }

    override fun encode(rawPassword: CharSequence): String {
        return bCryptPasswordEncoder.encode(rawPassword)
    }
}
