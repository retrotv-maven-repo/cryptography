package dev.retrotv.crypt.twe.aes;

import dev.retrotv.common.Log;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.TestInstance;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
class AESCFBTest extends Log {
    private final Set<byte[]> encryptedAllData128 = new HashSet<>();
    private final Set<byte[]> encryptedAllData192 = new HashSet<>();
    private final Set<byte[]> encryptedAllData256 = new HashSet<>();

    @DisplayName("AES/CFB-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescfb128_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCFB aes = new AESCFB(128);
        Key key = aes.generateKey();
        AlgorithmParameterSpec spec = aes.generateSpec();

        byte[] encryptedData = aes.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(aes.decrypt(encryptedData, key, spec));

        assertEquals(message, originalMessage);

        encryptedAllData128.add(encryptedData);

        if (repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
            log.info("마지막 테스트");
            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
            log.info("암호화 된 데이터 개수 : " + encryptedAllData128.size());

            if (repetitionInfo.getTotalRepetitions() != encryptedAllData128.size()) { fail(); }

            encryptedAllData128.clear();
        }
    }

    @DisplayName("AES/CFB-192 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescfb192_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCFB aes = new AESCFB(192);
        Key key = aes.generateKey();
        AlgorithmParameterSpec spec = aes.generateSpec();

        byte[] encryptedData = aes.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(aes.decrypt(encryptedData, key, spec));

        assertEquals(message, originalMessage);

        encryptedAllData192.add(encryptedData);

        if (repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
            log.info("마지막 테스트");
            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
            log.info("암호화 된 데이터 개수 : " + encryptedAllData192.size());

            if (repetitionInfo.getTotalRepetitions() != encryptedAllData192.size()) { fail(); }

            encryptedAllData192.clear();
        }
    }

    @DisplayName("AES/CFB-256 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescfb256_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCFB aes = new AESCFB(256);
        Key key = aes.generateKey();
        AlgorithmParameterSpec spec = aes.generateSpec();

        byte[] encryptedData = aes.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(aes.decrypt(encryptedData, key, spec));

        assertEquals(message, originalMessage);

        encryptedAllData256.add(encryptedData);

        if (repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
            log.info("마지막 테스트");
            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
            log.info("암호화 된 데이터 개수 : " + encryptedAllData256.size());

            if (repetitionInfo.getTotalRepetitions() != encryptedAllData256.size()) { fail(); }

            encryptedAllData256.clear();
        }
    }
}
