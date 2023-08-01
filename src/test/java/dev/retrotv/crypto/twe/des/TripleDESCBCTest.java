package dev.retrotv.crypto.twe.des;

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
class TripleDESCBCTest extends Log {
    private final Set<byte[]> encryptedAllData = new HashSet<>();

    @DisplayName("DESede/CBC 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void triple_descbc_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        TripleDESCBC des = new TripleDESCBC();
        Key key = des.generateKey();
        AlgorithmParameterSpec spec = des.generateSpec();
        des.dataPadding();

        byte[] encryptedData = des.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(des.decrypt(encryptedData, key, spec));

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
