package dev.retrotv.crypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public interface TwoWayEncryption {

    default String encrypt(String text, String key) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return new String(Base64.getEncoder().encode(encrypt(data, key)));
    }

    byte[] encrypt(byte[] data, String key);

    default String decrypt(String encryptedText, String key) {
        byte[] data = Base64.getDecoder().decode(encryptedText.getBytes(StandardCharsets.UTF_8));
        return new String(decrypt(data, key));
    }

    byte[] decrypt(byte[] encryptedData, String key);

    String generateKey();
}
