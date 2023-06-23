package dev.retrotv.crypt.twe.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.enums.SecurityStrength;

class AESGCMTest extends AESTest {
    private static final String MESSAGE = "The lazy dog jumps over the brown fox!";
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;

    @Test
    @DisplayName("AES-128 CBC 알고리즘 암복호화 테스트")
    void aesgcm128() throws Exception {
        RandomValue rv = new RandomValue();
        rv.generate(SecurityStrength.HIGH, 16);
        byte[] key = rv.getBytes();

        byte[] iv = new byte[GCM_IV_LENGTH];
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encryptedData = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decryptedMessage = cipher.doFinal(encryptedData);

        log.info("복호화: " + new String(decryptedMessage));
    }

    @Test
    @DisplayName("AES-192 CBC 알고리즘 암복호화 테스트")
    void aesgcm196() throws Exception {
        RandomValue rv = new RandomValue();
        rv.generate(SecurityStrength.HIGH, 24);
        byte[] key = rv.getBytes();

        byte[] iv = new byte[GCM_IV_LENGTH];
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encryptedData = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decryptedMessage = cipher.doFinal(encryptedData);

        log.info("복호화: " + new String(decryptedMessage));
    }

    @Test
    @DisplayName("AES-256 CBC 알고리즘 암복호화 테스트")
    void aesgcm256() throws Exception {
        RandomValue rv = new RandomValue();
        rv.generate(SecurityStrength.HIGH, 32);
        byte[] key = rv.getBytes();

        byte[] iv = new byte[GCM_IV_LENGTH];
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encryptedData = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decryptedMessage = cipher.doFinal(encryptedData);

        log.info("복호화: " + new String(decryptedMessage));
    }
}
