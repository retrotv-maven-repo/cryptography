package dev.retrotv.crypto.password.pbkdf2;

import dev.retrotv.crypto.password.enums.SecretKeyFactoryAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Pbkdf2PasswordEncoderTest {

    @Test
    @DisplayName("Pbkdf2PasswordEncoder() 테스트")
    void test_pbkdf2PasswordEncoder() {
        Pbkdf2PasswordEncoder passwordEncoder = new Pbkdf2PasswordEncoder();
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm) 테스트")
    void test_pbkdf2PasswordEncoder1() {
        Pbkdf2PasswordEncoder passwordEncoder = new Pbkdf2PasswordEncoder("", 16, 310000, SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1);
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm) 테스트")
    void test_pbkdf2PasswordEncoder2() {
        Pbkdf2PasswordEncoder passwordEncoder = new Pbkdf2PasswordEncoder("", 16, 310000, SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm) 테스트")
    void test_pbkdf2PasswordEncoder3() {
        Pbkdf2PasswordEncoder passwordEncoder = new Pbkdf2PasswordEncoder("", 16, 310000, SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512);
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }
}

