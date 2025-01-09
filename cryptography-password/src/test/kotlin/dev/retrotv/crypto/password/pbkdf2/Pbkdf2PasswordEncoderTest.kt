package dev.retrotv.crypto.password.pbkdf2

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*
import dev.retrotv.crypto.password.enums.SecretKeyFactoryAlgorithm.*

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
    fun test_pbkdf2PasswordEncoder1() {
        val passwordEncoder = Pbkdf2PasswordEncoder("", 16, 310000, PBKDF2WithHmacSHA1)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm) 테스트")
    fun test_pbkdf2PasswordEncoder2() {
        val passwordEncoder = Pbkdf2PasswordEncoder("", 16, 310000, PBKDF2WithHmacSHA256)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm) 테스트")
    fun test_pbkdf2PasswordEncoder3() {
        val passwordEncoder = Pbkdf2PasswordEncoder("", 16, 310000, PBKDF2WithHmacSHA512)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }
}