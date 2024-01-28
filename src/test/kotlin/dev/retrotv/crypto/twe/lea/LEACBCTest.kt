package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test


internal class LEACBCTest {
    @Test
    @DisplayName("LEACBC-128 암복호화 테스트")
    fun kisa_leacbc128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded, iv.iv)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded, iv.iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACBC-192 암복호화 테스트")
    fun kisa_leacbc192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded, iv.iv)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded, iv.iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACBC-256 암복호화 테스트")
    fun kisa_leacbc256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded, iv.iv)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded, iv.iv))
        Assertions.assertEquals(message, originalMessage)
    }
}
