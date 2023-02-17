package dev.retrotv.crypt;

import dev.retrotv.crypt.random.Salt;
import dev.retrotv.crypt.random.SecurityStrength;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public interface OneWayEncryption {

    default String encrypt(String text) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return new String(Base64.getEncoder().encode(encrypt(data)));
    }

    byte[] encrypt(byte[] data);

    default String encrypt(String text, String salt) {
        return encrypt(text.concat(salt));
    }

    default String generateSalt(SecurityStrength securityStrength, int len) {
        return Salt.generate(securityStrength, len);
    }
}
