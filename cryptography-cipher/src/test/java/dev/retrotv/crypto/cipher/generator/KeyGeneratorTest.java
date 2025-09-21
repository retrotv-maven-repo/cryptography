package dev.retrotv.crypto.cipher.generator;

import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.exception.GenerateException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyGeneratorTest {
    @Test
    @DisplayName("Exception 발생 테스트")
    void test_generateException() {
        assertThrows(IllegalArgumentException.class, () -> KeyGenerator.generateKey(4));
        assertThrows(GenerateException.class, () -> KeyGenerator.generateKey(ECipher.AES));
        assertThrows(GenerateException.class, () -> KeyGenerator.generateKey(ECipher.ARIA));
        assertThrows(GenerateException.class, () -> KeyGenerator.generateKey(ECipher.LEA));
    }

    @Test
    @DisplayName("key 생성 테스트")
    void test_generateKey() {
        byte[] key = KeyGenerator.generateKey(ECipher.AES, 16);
        assertEquals(16, key.length);

        key = KeyGenerator.generateKey(ECipher.DES);
        assertEquals(8, key.length);

        key = KeyGenerator.generateKey(ECipher.SEED);
        assertEquals(16, key.length);
    }
}

