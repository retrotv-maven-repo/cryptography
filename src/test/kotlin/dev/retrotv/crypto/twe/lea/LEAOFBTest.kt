package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class LEAOFBTest {

    @Test
    @DisplayName("LEAOFB-128 암복호화 테스트")
    fun leaofb128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAOFB(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAOFB-192 암복호화 테스트")
    fun leaofb192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAOFB(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAOFB-256 암복호화 테스트")
    fun leaofb256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAOFB(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }
}
