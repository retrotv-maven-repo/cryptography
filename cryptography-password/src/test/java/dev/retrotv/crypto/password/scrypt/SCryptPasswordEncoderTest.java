package dev.retrotv.crypto.password.scrypt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SCryptPasswordEncoderTest {

    @Test
    @DisplayName("SCryptPasswordEncoder() 생성자 테스트")
    void test_constructor() {
        SCryptPasswordEncoder passwordEncoder = new SCryptPasswordEncoder();
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }

    @Test
    @DisplayName("SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength) 생성자 테스트")
    void test_constructor_with_params() {
        SCryptPasswordEncoder passwordEncoder = new SCryptPasswordEncoder(65536, 8, 1, 32, 64);
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
    }
}

