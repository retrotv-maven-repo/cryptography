package dev.retrotv.crypt.twe.rsa;

import dev.retrotv.common.Log;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RSA2048Test extends Log {

    @Test
    @DisplayName("RSA-2048 암복호화 테스트")
    void test_rsa_2048() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";

        RSA2048 rsa = new RSA2048();
        KeyPair keyPair = rsa.generateKeyPair();

        String encryptedMessage = rsa.encrypt(message, keyPair.getPublic().getEncoded());
        log.info("암호화 된 메시지: " + encryptedMessage);

        String decryptedMessage = rsa.decrypt(encryptedMessage, keyPair.getPrivate().getEncoded());
        log.info("복호화 된 메시지: " + decryptedMessage);

        assertEquals(message, decryptedMessage);
    }
}
