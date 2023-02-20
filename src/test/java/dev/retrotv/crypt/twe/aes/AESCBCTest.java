package dev.retrotv.crypt.twe.aes;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.TwoWayEncryption;
import org.junit.jupiter.api.RepetitionInfo;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class AESCBCTest extends Log {
    protected static final Set<String> encryptedData = new HashSet<>();

    void encryptDecryptTest(TwoWayEncryption twe, RepetitionInfo repetitionInfo) {
        log.info("암호화 알고리즘: " + twe.getClass().getSimpleName());

        String message = "The lazy dog jumps over the brown fox!";
        String key = twe.generateKey();

        log.info("생성 된 키: " + key);

        String encryptedMessage = twe.encrypt(message, key);

        log.info("원본 메시지: " + message);
        log.info("암호화 된 메시지: " + encryptedMessage);

        assertNotEquals(message, encryptedMessage);

        String decryptedMessage = twe.decrypt(encryptedMessage, key);

        log.info("원본 메시지: " + message);
        log.info("암호화 된 메시지: " + encryptedMessage);
        log.info("복호화 된 메시지: " + decryptedMessage);

        assertEquals(message, decryptedMessage);

        /*
         * 반복된 테스트의 암호화 된 메시지를 List<String>에 저장하고 마지막 테스트에서 중복된 값이 있는지 체크합니다.
         * 중복된 값이 나온다면, Key 생성 알고리즘의 랜덤성에 문제가 있는 것이므로 Key 생성 알고리즘을 보완해야 합니다.
         */
        encryptedData.add(encryptedMessage);
        if(repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
            log.info("마지막 테스트");
            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
            log.info("암호화 된 데이터 개수 : " + encryptedData.size());
            if(repetitionInfo.getCurrentRepetition() != encryptedData.size()) { fail(); }
        }
    }
}
