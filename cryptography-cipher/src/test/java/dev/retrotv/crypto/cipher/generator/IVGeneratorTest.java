package dev.retrotv.crypto.cipher.generator;

import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.exception.GenerateException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IVGeneratorTest {
    @Test
    @DisplayName("Exception 발생 테스트")
    void test_generateException() {
        assertThrows(IllegalArgumentException.class, () -> IVGenerator.generateIV(4));
        assertThrows(GenerateException.class, () -> IVGenerator.generateIV(ECipher.AES, EMode.ECB));
        assertThrows(GenerateException.class, () -> IVGenerator.generateIV(ECipher.DES, EMode.CCM));
    }

    @Test
    @DisplayName("iv 생성 테스트")
    void test_generateKey() {
        byte[] key = IVGenerator.generateIV(ECipher.AES, EMode.CBC);
        assertEquals(16, key.length);

        key = IVGenerator.generateIV(ECipher.AES, EMode.CCM);
        assertEquals(12, key.length);

        key = IVGenerator.generateIV(ECipher.DES, EMode.CBC);
        assertEquals(8, key.length);
    }
}

