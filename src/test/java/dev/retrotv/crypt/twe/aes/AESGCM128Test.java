package dev.retrotv.crypt.twe.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.TestInstance;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

class AESGCM128Test {

    @DisplayName("AES/GCM-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aesgcm128_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESGCM aesgcm = new AESGCM128();
        Key key = aesgcm.generateKey();
        AlgorithmParameterSpec gcm = aesgcm.generateSpec();

        byte[] encryptedData = aesgcm.encrypt(message.getBytes(), key, gcm);
        String originalMessage = new String(aesgcm.decrypt(encryptedData, key, gcm));

        assertEquals(message, originalMessage);
    }
}
