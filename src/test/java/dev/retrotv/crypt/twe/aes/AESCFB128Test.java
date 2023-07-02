package dev.retrotv.crypt.twe.aes;

import dev.retrotv.common.Log;
import dev.retrotv.utils.SecureRandomUtil;
import org.junit.jupiter.api.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
class AESCFB128Test extends Log {

    private final Set<byte[]> encryptedAllData = new HashSet<>();

    @DisplayName("AES/CFB-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescfb128_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCFB aescfb = new AESCFB128();
        Key key = aescfb.generateKey();
        AlgorithmParameterSpec spec = aescfb.generateSpec();

        byte[] encryptedData = aescfb.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(aescfb.decrypt(encryptedData, key, spec));

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
