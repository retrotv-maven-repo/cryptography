package dev.retrotv.crypt.twe.rsa;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.exception.KeyGenerateException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RSATest {

    @Test
    @DisplayName("RSA-1024 암복호화 테스트")
    void rsa1024_test() throws KeyGenerateException, CryptFailException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator(1024);
        String message = "The lazy dog jumps over the brown fox!";
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSACipher rsa = new RSACipher();
        byte[] encryptedData = rsa.encrypt(message.getBytes(), keyPair.getPublic());
        String originalMessage = new String(rsa.decrypt(encryptedData, keyPair.getPrivate()));

        assertEquals(message, originalMessage);
    }

    @Test
    @DisplayName("RSA-2048 암복호화 테스트")
    void rsa2048_test() throws KeyGenerateException, CryptFailException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator(2048);
        String message = "The lazy dog jumps over the brown fox!";
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSACipher rsa = new RSACipher();
        byte[] encryptedData = rsa.encrypt(message.getBytes(), keyPair.getPublic());
        String originalMessage = new String(rsa.decrypt(encryptedData, keyPair.getPrivate()));

        assertEquals(message, originalMessage);
    }
}
