package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.generator.IVGenerator;
import dev.retrotv.crypto.cipher.generator.KeyGenerator;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class Chacha20Poly1305Test {
    private final String plainText = "The quick brown fox jumps over the lazy dog";

    @Test
    @DisplayName("Chacha20-Poly1305 암호화 테스트")
    void test_chacha20poly1305() {
        Chacha20Poly1305 chacha20 = new Chacha20Poly1305();
        byte[] key = KeyGenerator.generateKey(32);
        byte[] iv = IVGenerator.generateIV(12);
        byte[] aad = IVGenerator.generateIV(16);
        ParamWithIV params = new ParamWithIV(key, iv);

        chacha20.updateAAD(aad);
        Result encrypted = chacha20.encrypt(plainText.getBytes(), params);

        chacha20 = new Chacha20Poly1305();
        chacha20.updateAAD(aad);
        Result decrypted = chacha20.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    @Test
    @DisplayName("Chacha20-Poly1305 암호화 테스트 - 잘못된 Param 객체 전달")
    void test_chacha20poly1305InvalidParam() {
        Chacha20Poly1305 chacha20 = new Chacha20Poly1305();
        byte[] key = KeyGenerator.generateKey(32);
        Param params = new Param(key);

        byte[] textData = plainText.getBytes();
        assertThrows(
            IllegalArgumentException.class, () -> chacha20.encrypt(textData, params)
        );
    }

    @Test
    @DisplayName("Chacha20-Poly1305 스트림 암호화 테스트")
    void testEncryptAndDecryptInputStream() throws UnsupportedEncodingException {
        
        // 준비
        byte[] key = KeyGenerator.generateKey(32); // Chacha20-Poly1305는 32바이트 사용
        byte[] iv = IVGenerator.generateIV(12);
        byte[] aad = IVGenerator.generateIV(16);
        ParamWithIV param = new ParamWithIV(key, iv);
        Chacha20Poly1305 chacha20 = new Chacha20Poly1305();

        byte[] plain = "Hello Chacha20 Stream Cipher!".getBytes();

        // 암호화
        ByteArrayInputStream plainIn = new ByteArrayInputStream(plain);
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        chacha20.updateAAD(aad);
        chacha20.encrypt(plainIn, cipherOut, param);
        byte[] cipherBytes = cipherOut.toByteArray();

        // 복호화
        chacha20 = new Chacha20Poly1305();
        ByteArrayInputStream cipherIn = new ByteArrayInputStream(cipherBytes);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        chacha20.updateAAD(aad);
        chacha20.decrypt(cipherIn, plainOut, param);
        byte[] decrypted = plainOut.toByteArray();

        // 검증
        assertArrayEquals(plain, Arrays.copyOf(decrypted, plain.length));
    }
}

