package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.generator.KeyGenerator;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.result.Result;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S1874")
class RC4Test {

    @Test
    @DisplayName("Chacha20 암호화 테스트")
    void test_chacha20() {
        String plainText = "The quick brown fox jumps over the lazy dog";

        RC4 rc4 = new RC4();
        byte[] key = KeyGenerator.generateKey(32);
        Param params = new Param(key);

        Result encrypted = rc4.encrypt(plainText.getBytes(), params);
        Result decrypted = rc4.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }
}

