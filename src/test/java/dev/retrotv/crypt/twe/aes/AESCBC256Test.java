package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import org.junit.jupiter.api.*;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

class AESCBC256Test {

    @DisplayName("AES/CBC-256 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescbc256_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCBC aescbc = new AESCBC256();
        Key key = aescbc.generateKey();
        AlgorithmParameterSpec iv = aescbc.generateSpec();

        byte[] encryptedData = aescbc.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(aescbc.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);
    }
}
