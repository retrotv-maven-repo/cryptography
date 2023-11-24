package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class LEAECBTest {
    @Test
    @DisplayName("LEAECB-128 암복호화 테스트")
    @Throws(Exception::class)
    fun leaecb128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(128)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAECB-192 암복호화 테스트")
    @Throws(Exception::class)
    fun leaecb192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(192)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAECB-256 암복호화 테스트")
    @Throws(Exception::class)
    fun leaecb256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(256)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }
}
