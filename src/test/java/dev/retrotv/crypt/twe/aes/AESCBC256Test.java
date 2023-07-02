package dev.retrotv.crypt.twe.aes;

import org.junit.jupiter.api.*;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESCBC256Test {

    @DisplayName("AES/CBC-256 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescbc256_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCBC aescbc = new AESCBC256();
        Key key = aescbc.generateKey();
        AlgorithmParameterSpec spec = aescbc.generateSpec();

        byte[] encryptedData = aescbc.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(aescbc.decrypt(encryptedData, key, spec));

        assertEquals(message, originalMessage);
    }
}
