package dev.retrotv.crypt.twe.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESGCM256Test {

    @DisplayName("AES/GCM-256 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aesgcm256_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESGCM aesgcm = new AESGCM256();
        Key key = aesgcm.generateKey();
        AlgorithmParameterSpec gcm = aesgcm.generateSpec();

        byte[] encryptedData = aesgcm.encrypt(message.getBytes(), key, gcm);
        String originalMessage = new String(aesgcm.decrypt(encryptedData, key, gcm));

        assertEquals(message, originalMessage);
    }
}
