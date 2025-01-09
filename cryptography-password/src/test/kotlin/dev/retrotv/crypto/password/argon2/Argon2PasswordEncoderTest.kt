package dev.retrotv.crypto.password.argon2

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*

class Argon2PasswordEncoderTest {

    @Test
    @DisplayName("Argon2PasswordEncoder() 테스트")
    fun test_constructor() {
        val passwordEncoder = Argon2PasswordEncoder()
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations) 테스트")
    fun test_constructor_with_params() {
        val passwordEncoder = Argon2PasswordEncoder(16, 32, 1, 16384, 2)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }
}