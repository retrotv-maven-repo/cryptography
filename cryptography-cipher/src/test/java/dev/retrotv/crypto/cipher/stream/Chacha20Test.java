package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.generator.IVGenerator;
import dev.retrotv.crypto.cipher.generator.KeyGenerator;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
}

