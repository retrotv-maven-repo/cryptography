package dev.retrotv.crypt.twe.lea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LEACBCTest {

    @Test
    @DisplayName("LEACBC-128 암복호화 테스트")
    void leacbc128_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACBC lea = new LEACBC(128);
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();
        lea.dataPadding();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEACBC-192 암복호화 테스트")
    void leacbc192_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACBC lea = new LEACBC(192);
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();
        lea.dataPadding();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("LEACBC-256 암복호화 테스트")
    void leacbc256_test() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        LEACBC lea = new LEACBC(256);
        Key key = lea.generateKey();
        IvParameterSpec iv = lea.generateSpec();
        lea.dataPadding();

        byte[] encryptedData = lea.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(lea.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }
}
