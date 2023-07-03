package dev.retrotv.crypt.twe.lea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LEACTRTest {

    @Test
    @DisplayName("LEACTR-128 암복호화 테스트")
    void leactr128_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACTR lea = new LEACTR128();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEACTR-192 암복호화 테스트")
    void leactr192_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACTR lea = new LEACTR192();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEACTR-256 암복호화 테스트")
    void leactr256_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACTR lea = new LEACTR256();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }
}
