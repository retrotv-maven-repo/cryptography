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

/*

/*
 * BCrypt 알고리즘으로 암호화 하기 위한 [PasswordEncoder] 구현체.
 */

import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.data.utils.StringUtils
import dev.retrotv.utils.generate

class BCrypt : PasswordEncoder {
    private var cost = 10

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else {
            val salt = extractSalt(encodedPassword)
            val generatedValue = org.bouncycastle.crypto.generators.BCrypt.generate(
                StringUtils.toByteArray(rawPassword.toString()), salt, cost
            )

            return ByteUtils.toHexString(salt) + ByteUtils.toHexString(generatedValue) == encodedPassword
        }
    }

    override fun encode(rawPassword: CharSequence): String {
        val salt = generate(16)
        val hashedValue = org.bouncycastle.crypto.generators.BCrypt.generate(
            StringUtils.toByteArray(rawPassword.toString()), salt, cost
        )

        val generatedValue = ByteArray(salt.size + hashedValue.size)
        System.arraycopy(salt, 0, generatedValue, 0, salt.size)
        System.arraycopy(hashedValue, 0, generatedValue, salt.size, hashedValue.size)

        return ByteUtils.toHexString(generatedValue)
    }

    fun setCost(cost: Int) {
        this.cost = cost
    }

    private fun extractSalt(encodedPassword: String): ByteArray {
        val hashedByte = StringUtils.hexStringToByteArray(encodedPassword)
        val salt = ByteArray(16)
        System.arraycopy(hashedByte, 0, salt, 0, 16)

        return salt
    }
}
*/
