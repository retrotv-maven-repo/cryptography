package dev.retrotv.crypto.owe.kdf.scrypt

import dev.retrotv.crypto.owe.kdf.KDF
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder

/**
 * SCrypt 알고리즘으로 암호화 하기 위한 [KDF] 추상 클래스의 구현체 입니다.
 * Spring Security의 [PasswordEncoder]와 호환됩니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class SCrypt : KDF {
    private val sCryptPasswordEncoder: SCryptPasswordEncoder

    constructor() {
        sCryptPasswordEncoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8()
    }

    constructor(cpuCost: Int, memoryCost: Int, parallelization: Int, keyLength: Int, saltLength: Int) {
        sCryptPasswordEncoder = SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength)
    }

    override fun encode(rawPassword: CharSequence): String {
        return sCryptPasswordEncoder.encode(rawPassword)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else sCryptPasswordEncoder.matches(rawPassword, encodedPassword)
    }
}
