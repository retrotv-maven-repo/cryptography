package dev.retrotv.crypt.twe.lea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LEAGCMTest {

    @Test
    @DisplayName("LEAGCM-128 암복호화 테스트")
    void leagcm128_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAGCM lea = new LEAGCM(128);
        Key key = lea.generateKey();
        GCMParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEAGCM-192 암복호화 테스트")
    void leagcm192_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAGCM lea = new LEAGCM(192);
        Key key = lea.generateKey();
        GCMParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEAGCM-256 암복호화 테스트")
    void leagcm256_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAGCM lea = new LEAGCM(256);
        Key key = lea.generateKey();
        GCMParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }
}
