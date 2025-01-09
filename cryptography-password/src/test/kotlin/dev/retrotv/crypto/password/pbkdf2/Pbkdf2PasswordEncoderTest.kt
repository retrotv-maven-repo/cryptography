package dev.retrotv.crypto.password.pbkdf2

import dev.retrotv.crypto.password.enums.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*

class Pbkdf2PasswordEncoderTest {

    @Test
    @DisplayName("Pbkdf2PasswordEncoder() 테스트")
    fun test_pbkdf2PasswordEncoder() {
        val passwordEncoder = Pbkdf2PasswordEncoder()
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm) 테스트")
    fun test_pbkdf2PasswordEncoder_secret_saltLength_iterations_secretKeyFactoryAlgorithm() {
        val passwordEncoder = Pbkdf2PasswordEncoder("", 16, 310000, PBKDF2WithHmacSHA256)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }
}