package dev.retrotv.crypto.encryption.generator

import dev.retrotv.crypto.enums.ECipher.AES
import dev.retrotv.crypto.enums.ECipher.DES
import dev.retrotv.crypto.enums.EMode.*
import dev.retrotv.crypto.exception.GenerateException
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

class IVGeneratorTest {

    @Test
    @DisplayName("Exception 발생 테스트")
    fun test_generateException() {
        assertThrows(IllegalArgumentException::class.java) {
            generateIV(4)
        }

        assertThrows(GenerateException::class.java) {
            generateIV(AES, ECB)
        }

        assertThrows(GenerateException::class.java) {
            generateIV(DES, CCM)
        }
    }

    @Test
    @DisplayName("iv 생성 테스트")
    fun test_generateKey() {
        var key = generateIV(AES, CBC)
        assert(key.size == 16)

        key = generateIV(AES, CCM)
        assert(key.size == 12)

        key = generateIV(DES, CBC)
        assert(key.size == 8)
    }
}