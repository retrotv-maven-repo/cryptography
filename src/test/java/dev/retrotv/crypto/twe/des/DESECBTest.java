package dev.retrotv.crypto.twe.des;

import dev.retrotv.common.Log;
import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.twe.aes.AESECB;
import dev.retrotv.enums.EncodeFormat;
import org.junit.jupiter.api.*;

import java.security.Key;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
class DESECBTest extends Log {
    private final Set<byte[]> encryptedAllData = new HashSet<>();

    @DisplayName("DES/ECB 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void desecb_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        DES des = new DESECB();
        Key key = des.generateKey();
        des.dataPadding();

        byte[] encryptedData = des.encrypt(message.getBytes(), key, null);
        String originalMessage = new String(des.decrypt(encryptedData, key, null));

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
