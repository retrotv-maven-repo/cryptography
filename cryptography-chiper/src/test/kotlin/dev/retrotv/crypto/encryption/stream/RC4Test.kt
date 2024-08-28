package dev.retrotv.crypto.encryption.stream

import dev.retrotv.crypto.encryption.generator.generateKey
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class RC4Test {
    private val plainText = "The quick brown fox jumps over the lazy dog"

    @Test
    @DisplayName("Chacha20 암호화 테스트")
    fun test_chacha20() {
        val rc4 = RC4()
        val key = generateKey(32)

        val encrypted = rc4.encrypt(plainText.toByteArray(), key)
        val decrypted = rc4.decrypt(encrypted, key)

        assertEquals(plainText, String(decrypted))
    }
}