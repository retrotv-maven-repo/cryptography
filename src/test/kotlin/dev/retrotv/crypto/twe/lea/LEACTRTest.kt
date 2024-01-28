package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class LEACTRTest {

    @Test
    @DisplayName("LEACTR-128 암복호화 테스트")
    fun leactr128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACTR(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val params = ParamsWithIV(key.encoded, iv.iv)

        val encryptedData = lea.encrypt(message.toByteArray(), params)
        val originalMessage = String(lea.decrypt(encryptedData, params))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACTR-192 암복호화 테스트")
    fun leactr192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACTR(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val params = ParamsWithIV(key.encoded, iv.iv)

        val encryptedData = lea.encrypt(message.toByteArray(), params)
        val originalMessage = String(lea.decrypt(encryptedData, params))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACTR-256 암복호화 테스트")
    fun leactr256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACTR(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val params = ParamsWithIV(key.encoded, iv.iv)

        val encryptedData = lea.encrypt(message.toByteArray(), params)
        val originalMessage = String(lea.decrypt(encryptedData, params))
        Assertions.assertEquals(message, originalMessage)
    }
}
