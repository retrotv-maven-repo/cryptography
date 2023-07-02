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

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
class AESCBC128Test extends Log {

    private final Set<byte[]> encryptedAllData = new HashSet<>();

    @Test
    @DisplayName("AES/CTR-128")
    void aesctr128_test() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String message = "The lazy dog jumps over the brown fox!";
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        Key key = new SecretKeySpec(SecureRandomUtil.generate(16), "AES");
        IvParameterSpec spec = new IvParameterSpec(SecureRandomUtil.generate(16));
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] encryptedData = cipher.doFinal(message.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        String originalMessage = new String(cipher.doFinal(encryptedData));

        assertEquals(message, originalMessage);
    }

    @DisplayName("AES/CBC-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void aescbc128_100_repeat_test(RepetitionInfo repetitionInfo) throws Exception {
        String message = "The lazy dog jumps over the brown fox!";
        AESCBC aescbc = new AESCBC128();
        Key key = aescbc.generateKey();
        AlgorithmParameterSpec spec = aescbc.generateSpec();

        byte[] encryptedData = aescbc.encrypt(message.getBytes(), key, spec);
        String originalMessage = new String(aescbc.decrypt(encryptedData, key, spec));

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
