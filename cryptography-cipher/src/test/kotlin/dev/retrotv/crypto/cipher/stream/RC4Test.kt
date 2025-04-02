package dev.retrotv.crypto.cipher.stream

import dev.retrotv.crypto.cipher.generator.KeyGenerator.generateKey
import dev.retrotv.crypto.cipher.param.Param
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
        val params = Param(key)

        val encrypted = rc4.encrypt(plainText.toByteArray(), params)
        val decrypted = rc4.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }
}