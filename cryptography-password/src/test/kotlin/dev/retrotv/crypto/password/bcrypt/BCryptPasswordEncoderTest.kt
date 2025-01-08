package dev.retrotv.crypto.password.bcrypt

import dev.retrotv.crypto.password.enums.BCryptVersion

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class BCryptPasswordEncoderTest {

    @Test
    @DisplayName("BCryptPasswordEncoder 테스트")
    fun test_bcrypt() {
        val passwordEncoder = BCryptPasswordEncoder()
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(strength) 테스트")
    fun test_bcrypt_strength() {
        val passwordEncoder = BCryptPasswordEncoder(10)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(version) 테스트")
    fun test_bcrypt_version() {
        val passwordEncoder = BCryptPasswordEncoder(BCryptVersion.`$2A`)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(version, random) 테스트")
    fun test_bcrypt_version_random() {
        val passwordEncoder = BCryptPasswordEncoder(BCryptVersion.`$2A`, SecureRandom())
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(strength, random) 테스트")
    fun test_bcrypt_strength_random() {
        val passwordEncoder = BCryptPasswordEncoder(10, SecureRandom())
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(version, strength) 테스트")
    fun test_bcrypt_version_strength() {
        val passwordEncoder = BCryptPasswordEncoder(BCryptVersion.`$2A`, 10)
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(version, strength, random) 테스트")
    fun test_bcrypt_version_strength_random() {
        val passwordEncoder = BCryptPasswordEncoder(BCryptVersion.`$2A`, 10, SecureRandom())
        val rawPassword = "password"
        val encodedPassword = passwordEncoder.encode(rawPassword)

        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword))
    }
}