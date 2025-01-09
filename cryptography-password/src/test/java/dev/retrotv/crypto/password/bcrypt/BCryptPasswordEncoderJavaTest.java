package dev.retrotv.crypto.password.bcrypt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class BCryptPasswordEncoderJavaTest {
    @Test
    @DisplayName("Test BCryptPasswordEncoderJava")
    void testBCryptPasswordEncoderJava() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String password = "password";
        String encodedPassword = encoder.encode(password);

        assertTrue(encoder.matches(password, encodedPassword));
    }
}
