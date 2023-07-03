package dev.retrotv.crypt.twe.lea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LEAOFBTest {

    @Test
    @DisplayName("LEAOFB-128 암복호화 테스트")
    void leaofb128_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAOFB lea = new LEAOFB128();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEAOFB-192 암복호화 테스트")
    void leaofb192_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAOFB lea = new LEAOFB192();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEAOFB-256 암복호화 테스트")
    void leaofb256_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEAOFB lea = new LEAOFB256();
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }
}
