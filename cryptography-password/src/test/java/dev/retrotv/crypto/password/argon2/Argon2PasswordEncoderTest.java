package dev.retrotv.crypto.password.argon2;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Argon2PasswordEncoderTest {

    @Test
    @DisplayName("Argon2PasswordEncoder() 테스트")
    void test_constructor() {
        Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder();
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations) 테스트")
    void test_constructor_with_params() {
        Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder(16, 32, 1, 16384, 2);
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }
}
