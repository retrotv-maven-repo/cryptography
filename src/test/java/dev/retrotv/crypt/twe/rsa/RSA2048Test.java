package dev.retrotv.crypt.twe.rsa;

import dev.retrotv.common.Log;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RSA2048Test extends Log {

    @Test
    @DisplayName("RSA-2048 암복호화 테스트")
    void test_rsa_2048() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";

        RSA2048 rsa = new RSA2048();
        KeyPair keyPair = rsa.generateKeyPair();

        byte[] encryptedMessage = rsa.encrypt(message.getBytes(), keyPair.getPublic().getEncoded(), null);
        byte[] decryptedMessage = rsa.decrypt(encryptedMessage, keyPair.getPrivate().getEncoded(), null);

        assertEquals(message, new String(decryptedMessage));

        encryptedMessage = rsa.sign(message.getBytes(), keyPair.getPrivate());

        assertTrue(rsa.verify(message.getBytes(), encryptedMessage, keyPair.getPublic()));
    }
}
