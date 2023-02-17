package dev.retrotv.crypt.md;

import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.random.SecurityStrength;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

public class MD5Test {
    private static final Logger log = Logger.getGlobal();

    @RepeatedTest(5)
    @DisplayName("MD5 알고리즘 암호화 테스트")
    void md5EncryptTest() {
        String message = "The lazy dog jumps over the brown fox!";
        OneWayEncryption owe = new MD5();
        String salt = owe.generateSalt(SecurityStrength.HIGH, 20);

        String encryptedMessage = owe.encrypt(message, salt);
        log.info("암호화 된 메시지: " + encryptedMessage);
    }
}