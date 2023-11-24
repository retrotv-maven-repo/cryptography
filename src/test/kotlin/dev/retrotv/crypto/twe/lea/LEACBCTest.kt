package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class LEACBCTest {
    @Test
    @DisplayName("LEACBC-128 암복호화 테스트")
    @Throws(Exception::class)
    fun leacbc128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACBC-192 암복호화 테스트")
    @Throws(Exception::class)
    fun leacbc192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACBC-256 암복호화 테스트")
    @Throws(Exception::class)
    fun leacbc256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }
}
