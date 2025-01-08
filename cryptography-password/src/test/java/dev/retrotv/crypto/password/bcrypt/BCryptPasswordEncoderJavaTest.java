package dev.retrotv.crypto.password.bcrypt;

import dev.retrotv.crypto.password.enums.BCryptVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BCryptPasswordEncoderJavaTest {
    @Test
    @DisplayName("Test BCryptPasswordEncoderJava")
    void testBCryptPasswordEncoderJava() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String password = "password";
        String encodedPassword = encoder.encode(password);

        encoder.matches(password, encodedPassword);
    }
}
