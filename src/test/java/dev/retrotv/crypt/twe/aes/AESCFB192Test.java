package dev.retrotv.crypt.twe.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESCFB192Test {

    @DisplayName("AES/CFB-192 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescfb192_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCFB aescfb = new AESCFB192();
        Key key = aescfb.generateKey();
        AlgorithmParameterSpec spec = aescfb.generateSpec();

        byte[] encryptedData = aescfb.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(aescfb.decrypt(encryptedData, key, spec));

        assertEquals(message, originalMessage);
    }
}
