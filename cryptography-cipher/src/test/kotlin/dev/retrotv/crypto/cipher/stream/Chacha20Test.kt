package dev.retrotv.crypto.cipher.stream

import dev.retrotv.crypto.cipher.generator.IVGenerator.generateIV
import dev.retrotv.crypto.cipher.generator.KeyGenerator.generateKey
import dev.retrotv.crypto.cipher.param.ParamsWithIV
import dev.retrotv.crypto.cipher.stream.Chacha20
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
        val params = ParamsWithIV(key, iv)

        val encrypted = chacha20.encrypt(plainText.toByteArray(), params)
        val decrypted = chacha20.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }
}