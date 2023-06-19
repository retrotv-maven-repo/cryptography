package dev.retrotv.crypt.twe.aes;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.enums.SecurityStrength;
import org.junit.jupiter.api.RepetitionInfo;

import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class AESTest extends Log {
    protected static final Set<String> encryptedData = new HashSet<>();

    void encryptedDataWithIVTest(AESCBC aescbc) throws CryptFailException {
        String message = "The lazy dog jumps over the brown fox!";
        byte[] key = aescbc.generateKey(SecurityStrength.HIGH).getBytes(StandardCharsets.UTF_8);
        IvParameterSpec iv = aescbc.generateInitializationVector(SecurityStrength.HIGH);

        String encryptedMessage = aescbc.encrypt(message, key, iv);
        String decryptedMessage = aescbc.decrypt(encryptedMessage, key, iv);

        assertEquals(message, decryptedMessage);
    }

    void encryptDecryptTest(TwoWayEncryption twe, RepetitionInfo repetitionInfo) throws CryptFailException {
        log.info("암호화 알고리즘: " + twe.getClass().getSimpleName());

        String message = "The lazy dog jumps over the brown fox!";
        byte[] key = RandomValue.generate(SecurityStrength.HIGH).getBytes(StandardCharsets.UTF_8);

        log.info("생성 된 키: " + new String(key, StandardCharsets.UTF_8));
        log.info("키의 길이: " + key.length * 8);

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
         * 중복된 값이 나온다면, Key 생성 알고리즘의 무작위성에 문제가 있는 것이므로 Key 생성 알고리즘을 보완해야 합니다.
         */
        encryptedData.add(encryptedMessage);
        if(repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
            log.info("마지막 테스트");
            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
            log.info("암호화 된 데이터 개수 : " + encryptedData.size());
            if(repetitionInfo.getTotalRepetitions() != encryptedData.size()) { fail(); }

            encryptedData.clear();
        }
    }
}
