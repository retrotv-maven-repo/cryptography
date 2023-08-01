package dev.retrotv.crypto.twe.lea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LEAECBTest {

    @Test
    @DisplayName("LEAECB-128 암복호화 테스트")
    void leaecb128_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAECB lea = new LEAECB(128);
        Key key = lea.generateKey();
        lea.dataPadding();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key);
        String originalMessage = new String(lea.decrypt(encryptedData, key));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEAECB-192 암복호화 테스트")
    void leaecb192_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAECB lea = new LEAECB(192);
        Key key = lea.generateKey();
        lea.dataPadding();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key);
        String originalMessage = new String(lea.decrypt(encryptedData, key));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEAECB-256 암복호화 테스트")
    void leaecb256_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAECB lea = new LEAECB(256);
        Key key = lea.generateKey();
        lea.dataPadding();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key);
        String originalMessage = new String(lea.decrypt(encryptedData, key));

        assertEquals(message, originalMessage);
    }
}
