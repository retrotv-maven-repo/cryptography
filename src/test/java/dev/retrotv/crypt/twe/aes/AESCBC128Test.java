package dev.retrotv.crypt.twe.aes;

import dev.retrotv.common.Log;

import org.junit.jupiter.api.*;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
class AESCBC128Test extends Log {

    private final Set<byte[]> encryptedAllData = new HashSet<>();

    @DisplayName("AES/CBC-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescbc128_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCBC aescbc = new AESCBC128();
        Key key = aescbc.generateKey();
        AlgorithmParameterSpec iv = aescbc.generateSpec();

        byte[] encryptedData = aescbc.encrypt(message.getBytes(), key, iv);
        String originalMessage = new String(aescbc.decrypt(encryptedData, key, iv));

        assertEquals(message, originalMessage);

        encryptedAllData.add(encryptedData);

        if (repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
            log.info("마지막 테스트");
            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
            log.info("암호화 된 데이터 개수 : " + encryptedAllData.size());

            if (repetitionInfo.getTotalRepetitions() != encryptedAllData.size()) { fail(); }

            encryptedAllData.clear();
        }
    }
}
