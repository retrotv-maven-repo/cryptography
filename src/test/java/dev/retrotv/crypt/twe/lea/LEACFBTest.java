package dev.retrotv.crypt.twe.lea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LEACFBTest {

    @Test
    @DisplayName("LEACFB-128 암복호화 테스트")
    void leacfb128_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACFB lea = new LEACFB128();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEACFB-192 암복호화 테스트")
    void leacfb192_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACFB lea = new LEACFB192();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEACFB-256 암복호화 테스트")
    void leacfb256_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACFB lea = new LEACFB256();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }
}
