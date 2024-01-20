package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class LEACFBTest {
    @Test
    @DisplayName("LEACFB-128 암복호화 테스트")
    fun leacfb128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACFB(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACFB-192 암복호화 테스트")
    fun leacfb192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACFB(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACFB-256 암복호화 테스트")
    fun leacfb256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACFB(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }
}
