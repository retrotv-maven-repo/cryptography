package dev.retrotv.crypto.password.scrypt

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test


class SCryptPasswordEncoderTest {

    @Test
    @DisplayName("SCryptPasswordEncoder() 생성자 테스트")
    fun test_constructor() {
        val passwordEncoder = SCryptPasswordEncoder()
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength) 생성자 테스트")
    fun test_constructor_with_params() {
        val passwordEncoder = SCryptPasswordEncoder(65536, 8, 1, 32, 64)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertNotEquals(rawPassword, encodedPassword)
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }
}