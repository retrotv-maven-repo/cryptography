package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.generator.KeyGenerator;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.result.Result;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

@SuppressWarnings({ "java:S1874", "deprecation" })
class RC4Test {

    @Test
    @DisplayName("RC4 암호화 테스트")
    void test_rc4() {
        String plainText = "The quick brown fox jumps over the lazy dog";

        RC4 rc4 = new RC4();
        byte[] key = KeyGenerator.generateKey(32);
        Param params = new Param(key);

        Result encrypted = rc4.encrypt(plainText.getBytes(), params);
        Result decrypted = rc4.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    @Test
    @DisplayName("RC4 스트림 암호화 테스트")
    void testEncryptAndDecryptInputStream() {
        // 준비
        byte[] key = "testkey123456789".getBytes(); // RC4는 16바이트까지 권장
        Param param = new Param(key);
        RC4 rc4 = new RC4();

        byte[] plain = "Hello RC4 Stream Cipher!".getBytes();

        // 암호화
        ByteArrayInputStream plainIn = new ByteArrayInputStream(plain);
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        rc4.encrypt(plainIn, cipherOut, param);
        byte[] cipherBytes = cipherOut.toByteArray();

        // 복호화
        ByteArrayInputStream cipherIn = new ByteArrayInputStream(cipherBytes);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        rc4.decrypt(cipherIn, plainOut, param);
        byte[] decrypted = plainOut.toByteArray();

        // 검증
        assertArrayEquals(plain, decrypted);
    }
}

