package dev.retrotv.crypto.password.bcrypt

import dev.retrotv.crypto.password.PasswordEncoder
import dev.retrotv.crypto.password.enums.BCryptVersion
import dev.retrotv.crypto.password.enums.BCryptVersion.`$2A`
import dev.retrotv.crypto.password.enums.BCryptVersion.`$2B`
import dev.retrotv.crypto.password.enums.BCryptVersion.`$2Y`
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.security.SecureRandom

/**
 * BCrypt 해싱 함수를 사용하는 PasswordEncoder 구현.
 * BCryptPasswordEncoder는 라운드 횟수, 버전 및 SecureRandom 객체 매개변수를 제공할 수 있습니다.
 */
class BCryptPasswordEncoder : PasswordEncoder {
    private val encoder: BCryptPasswordEncoder

    /**
     * 기본 BCryptPasswordEncoder를 생성합니다.
     */
    constructor() {
        this.encoder = BCryptPasswordEncoder()
    }

    /**
     * 주어진 매개변수를 사용하여 BCryptPasswordEncoder를 생성합니다.
     * @param strength 라운드 횟수 (4 ~ 31)
     */
    constructor(strength: Int) {
        this.encoder = BCryptPasswordEncoder(strength)
    }

    /**
     * 주어진 매개변수를 사용하여 BCryptPasswordEncoder를 생성합니다.
     * @param version 버전 (2A, 2Y, 2B)
     */
    constructor(version: BCryptVersion) {
        this.encoder = BCryptPasswordEncoder(selectVersion(version))
    }

    /**
     * 주어진 매개변수를 사용하여 BCryptPasswordEncoder를 생성합니다.
     * @param version 버전 (2A, 2Y, 2B)
     * @param random SecureRandom 객체
     */
    constructor(version: BCryptVersion, random: SecureRandom) {
        this.encoder = BCryptPasswordEncoder(selectVersion(version), random)
    }

    /**
     * 주어진 매개변수를 사용하여 BCryptPasswordEncoder를 생성합니다.
     * @param strength 라운드 횟수 (4 ~ 31)
     * @param random SecureRandom 객체
     */
    constructor(strength: Int, random: SecureRandom) {
        this.encoder = BCryptPasswordEncoder(strength, random)
    }

    /**
     * 주어진 매개변수를 사용하여 BCryptPasswordEncoder를 생성합니다.
     * @param version 버전 (2A, 2Y, 2B)
     * @param strength 라운드 횟수 (4 ~ 31)
     */
    constructor(version: BCryptVersion, strength: Int) {
        this.encoder = BCryptPasswordEncoder(selectVersion(version), strength)
    }

    /**
     * 주어진 매개변수를 사용하여 BCryptPasswordEncoder를 생성합니다.
     * @param version 버전 (2A, 2Y, 2B)
     * @param strength 라운드 횟수 (4 ~ 31)
     * @param random SecureRandom 객체
     */
    constructor(version: BCryptVersion, strength: Int, random: SecureRandom) {
        this.encoder = BCryptPasswordEncoder(selectVersion(version), strength, random)
    }

    override fun encode(rawPassword: CharSequence): String {
        return this.encoder.encode(rawPassword)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return this.encoder.matches(rawPassword, encodedPassword)
    }

    private fun selectVersion(version: BCryptVersion): BCryptPasswordEncoder.BCryptVersion {
        return when (version) {
            `$2A` -> BCryptPasswordEncoder.BCryptVersion.`$2A`
            `$2Y` -> BCryptPasswordEncoder.BCryptVersion.`$2Y`
            `$2B` -> BCryptPasswordEncoder.BCryptVersion.`$2B`
        }
    }
}