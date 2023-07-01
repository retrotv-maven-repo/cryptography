package dev.retrotv.crypt.twe.aes;

import org.junit.jupiter.api.*;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESCBC192Test {

    @DisplayName("AES/CBC-192 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescbc192_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCBC aescbc = new AESCBC192();
        Key key = aescbc.generateKey();
        AlgorithmParameterSpec iv = aescbc.generateSpec();

        byte[] encryptedData = aescbc.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(aescbc.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }
}
