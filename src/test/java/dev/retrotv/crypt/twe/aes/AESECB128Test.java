package dev.retrotv.crypt.twe.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import java.security.Key;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESECB128Test {

    @DisplayName("AES/ECB-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aesecb128_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESECB aesecb = new AESECB128();
        Key key = aesecb.generateKey();

        byte[] encryptedData = aesecb.encrypt(message.getBytes(), key, null);
        String originalMessage = new String(aesecb.decrypt(encryptedData, key, null));

        assertEquals(message, originalMessage);
    }
}
