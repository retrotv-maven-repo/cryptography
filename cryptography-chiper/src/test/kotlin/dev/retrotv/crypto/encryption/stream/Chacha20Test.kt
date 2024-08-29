package dev.retrotv.crypto.encryption.stream

import dev.retrotv.crypto.encryption.generator.IVGenerator.generateIV
import dev.retrotv.crypto.encryption.generator.KeyGenerator.generateKey
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class Chacha20Test {
    private val plainText = "The quick brown fox jumps over the lazy dog"

    @Test
    @DisplayName("Chacha20 암호화 테스트")
    fun test_chacha20() {
        val chacha20 = Chacha20()
        val key = generateKey(32)
        val iv = generateIV(8)

        val encrypted = chacha20.encrypt(plainText.toByteArray(), key, iv)
        val decrypted = chacha20.decrypt(encrypted, key, iv)

        assertEquals(plainText, String(decrypted))
    }
}