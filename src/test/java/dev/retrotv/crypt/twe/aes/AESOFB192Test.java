package dev.retrotv.crypt.twe.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESOFB192Test {

    @DisplayName("AES/OFB-192 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aesofb192_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESOFB aesofb = new AESOFB192();
        Key key = aesofb.generateKey();
        AlgorithmParameterSpec spec = aesofb.generateSpec();

        byte[] encryptedData = aesofb.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(aesofb.decrypt(encryptedData, key, spec));

        assertEquals(message, originalMessage);
    }
}
