package dev.retrotv.crypto.password.bcrypt;

import dev.retrotv.crypto.password.enums.BCryptVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class BCryptPasswordEncoderTest {

    @Test
    @DisplayName("BCryptPasswordEncoder() 테스트")
    void test_bcrypt() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(strength) 테스트")
    void test_bcrypt_strength() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(version) 테스트")
    void test_bcrypt_version() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(BCryptVersion.$2A);
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(version, random) 테스트")
    void test_bcrypt_version_random() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(BCryptVersion.$2A, new SecureRandom());
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(strength, random) 테스트")
    void test_bcrypt_strength_random() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10, new SecureRandom());
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(version, strength) 테스트")
    void test_bcrypt_version_strength() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(BCryptVersion.$2Y, 10);
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("BCryptPasswordEncoder(version, strength, random) 테스트")
    void test_bcrypt_version_strength_random() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(BCryptVersion.$2B, 10, new SecureRandom());
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }
}

