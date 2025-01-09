package dev.retrotv.crypto.password.pbkdf2

import dev.retrotv.crypto.password.PasswordEncoder
import dev.retrotv.crypto.password.enums.SecretKeyFactoryAlgorithm
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder

import dev.retrotv.crypto.password.enums.SecretKeyFactoryAlgorithm.*

/**
 * Pbkdf2 해싱 함수를 사용하는 PasswordEncoder 구현.
 * 클라이언트는 선택적으로 사용할 비밀 값, salt의 길이, 반복 횟수 및 사용할 알고리즘을 제공할 수 있습니다.
 */
class Pbkdf2PasswordEncoder : PasswordEncoder {
    private val encoder: Pbkdf2PasswordEncoder

    /**
     * 기본 Pbkdf2PasswordEncoder를 생성합니다.
     */
    constructor() {
        this.encoder = Pbkdf2PasswordEncoder("", 16, 310000, selectSecretKeyFactoryAlgorithm(PBKDF2WithHmacSHA256))
    }

    /**
     * 주어진 매개변수를 사용하여 Pbkdf2PasswordEncoder를 생성합니다.
     * @param secret 비밀 값
     * @param saltLength 솔트 길이 (바이트 단위)
     * @param iterations 반복 횟수. 사용자는 자신의 시스템에서 약 0.5초가 걸리도록 설정해야 합니다.
     * @param secretKeyFactoryAlgorithm 사용할 알고리즘
     */
    constructor(
          secret: CharSequence
        , saltLength: Int
        , iterations: Int
        , secretKeyFactoryAlgorithm: SecretKeyFactoryAlgorithm
    ) {
        this.encoder = Pbkdf2PasswordEncoder(
              secret
            , saltLength
            , iterations
            , selectSecretKeyFactoryAlgorithm(secretKeyFactoryAlgorithm)
        )
    }

    override fun encode(rawPassword: CharSequence): String {
        return this.encoder.encode(rawPassword)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return this.encoder.matches(rawPassword, encodedPassword)
    }

    private fun selectSecretKeyFactoryAlgorithm(
        secretKeyFactoryAlgorithm: SecretKeyFactoryAlgorithm
    ): Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm {
        return when (secretKeyFactoryAlgorithm) {
            PBKDF2WithHmacSHA1 -> Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1
            PBKDF2WithHmacSHA256 -> Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256
            PBKDF2WithHmacSHA512 -> Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512
        }
    }
}