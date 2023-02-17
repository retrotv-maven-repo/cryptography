package dev.retrotv.crypt.md;

import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.random.SecurityStrength;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;

import java.util.logging.Logger;

public class MD2Test {
    private static final Logger log = Logger.getGlobal();

    @RepeatedTest(5)
    @DisplayName("MD2 알고리즘 암호화 테스트")
    void md5EncryptTest() {
        String message = "The lazy dog jumps over the brown fox!";
        OneWayEncryption owe = new MD2();
        String salt = owe.generateSalt(SecurityStrength.HIGH, 20);

        String encryptedMessage = owe.encrypt(message, salt);
        log.info("암호화 된 메시지: " + encryptedMessage);
    }
}
