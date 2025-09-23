package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.generator.IVGenerator;
import dev.retrotv.crypto.cipher.generator.KeyGenerator;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

class Chacha20Test {
    private final String plainText = "The quick brown fox jumps over the lazy dog";

    @Test
    @DisplayName("Chacha20 암호화 테스트")
    void test_chacha20() {
        Chacha20 chacha20 = new Chacha20();
        byte[] key = KeyGenerator.generateKey(32);
        byte[] iv = IVGenerator.generateIV(8);
        ParamWithIV params = new ParamWithIV(key, iv);

        Result encrypted = chacha20.encrypt(plainText.getBytes(), params);
        Result decrypted = chacha20.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    @Test
    @DisplayName("Chacha20 암호화 테스트 - 잘못된 Param 객체 전달")
    void test_chacha20_invalid_param() {
        Chacha20 chacha20 = new Chacha20();
        byte[] key = KeyGenerator.generateKey(32);
        Param params = new Param(key);

        assertThrows(IllegalArgumentException.class, () -> chacha20.encrypt(plainText.getBytes(), params));
    }

    @Test
    @DisplayName("Chacha20 스트림 암호화 테스트")
    void testEncryptAndDecryptInputStream() throws Exception {
        // 준비
        byte[] key = "testkey123456789".getBytes(); // Chacha20는 32바이트까지 권장
        byte[] iv = IVGenerator.generateIV(8);
        ParamWithIV param = new ParamWithIV(key, iv);
        Chacha20 chacha20 = new Chacha20();

        byte[] plain = "Hello Chacha20 Stream Cipher!".getBytes();

        // 암호화
        ByteArrayInputStream plainIn = new ByteArrayInputStream(plain);
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        chacha20.encrypt(plainIn, cipherOut, param);
        byte[] cipherBytes = cipherOut.toByteArray();

        // 복호화
        ByteArrayInputStream cipherIn = new ByteArrayInputStream(cipherBytes);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        chacha20.decrypt(cipherIn, plainOut, param);
        byte[] decrypted = plainOut.toByteArray();

        // 검증
        assertArrayEquals(plain, decrypted);
    }
}

