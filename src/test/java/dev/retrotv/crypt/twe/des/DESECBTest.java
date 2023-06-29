package dev.retrotv.crypt.twe.des;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.enums.SecurityStrength;

public class DESECBTest {
    @Test
    @DisplayName("DES/ECB 암복호화 테스트")
    void desecb_test() throws CryptFailException {
        String message = "The lazy dog jumps over the brown fox!";
        TwoWayEncryption twe = new DESECB();
        RandomValue rv = new RandomValue();
        rv.generate(SecurityStrength.HIGH, 8);
        byte[] key = rv.getBytes();
        byte[] encryptedData = twe.encrypt(message.getBytes(), key, null);
        String originalMessage = new String(twe.decrypt(encryptedData, key, null));

        assertEquals(message, originalMessage);
    }
}
