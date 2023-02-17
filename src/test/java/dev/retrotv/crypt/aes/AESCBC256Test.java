package dev.retrotv.crypt.aes;

import dev.retrotv.crypt.TwoWayEncryption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

public class AESCBC256Test {
    private static final Logger log = Logger.getGlobal();

    @RepeatedTest(100)
    @DisplayName("AES-256 CBC 알고리즘 암복호화 테스트")
    void AESCBC256EncryptDecryptTest() {
        TwoWayEncryption twe = new AESCBC256();

        String message = "The lazy dog jumps over the brown fox!";
        String key = twe.generateKey();

        log.info("생성 된 키: " + key);

        String encryptedMessage = twe.encrypt(message, key);

        log.info("원본 메시지: " + message);
        log.info("암호화 된 메시지: " + encryptedMessage);

        assertNotEquals(message, encryptedMessage);

        String decryptedMessage = twe.decrypt(encryptedMessage, key);

        log.info("원본 메시지: " + message);
        log.info("암호화 된 메시지: " + encryptedMessage);
        log.info("복호화 된 메시지: " + decryptedMessage);

        assertEquals(message, decryptedMessage);
    }
}
