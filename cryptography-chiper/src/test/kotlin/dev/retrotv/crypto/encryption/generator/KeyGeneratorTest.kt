package dev.retrotv.crypto.encryption.generator

import dev.retrotv.crypto.enums.ECipher.*
import dev.retrotv.crypto.exception.GenerateException
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Assertions.assertThrows
import kotlin.test.Test

class KeyGeneratorTest {

    @Test
    @DisplayName("Exception 발생 테스트")
    fun test_generateException() {
        assertThrows(IllegalArgumentException::class.java) {
            generateKey(4)
        }

        assertThrows(GenerateException::class.java) {
            generateKey(AES)
        }

        assertThrows(GenerateException::class.java) {
            generateKey(ARIA)
        }

        assertThrows(GenerateException::class.java) {
            generateKey(LEA)
        }
    }

    @Test
    @DisplayName("key 생성 테스트")
    fun test_generateKey() {
        var key = generateKey(AES, 16)
        assert(key.size == 16)

        key = generateKey(DES)
        assert(key.size == 8)

        key = generateKey(SEED)
        assert(key.size == 16)
    }
}