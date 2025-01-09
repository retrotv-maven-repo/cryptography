package dev.retrotv.crypto.password.pbkdf2

import dev.retrotv.crypto.password.PasswordEncoder
import dev.retrotv.crypto.password.enums.SecretKeyFactoryAlgorithm
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder

import dev.retrotv.crypto.password.enums.SecretKeyFactoryAlgorithm.*

class Pbkdf2PasswordEncoder : PasswordEncoder {
    private var encoder: Pbkdf2PasswordEncoder

    constructor() {
        this.encoder = Pbkdf2PasswordEncoder("", 16, 310000, selectSecretKeyFactoryAlgorithm(PBKDF2WithHmacSHA256))
    }

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