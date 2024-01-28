package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

internal class LEACCMTest {

    @Test
    @DisplayName("KISA LEAGCM-128 암복호화 테스트")
    fun kisa_leaccm128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded, iv.iv)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded, iv.iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEAGCM-192 암복호화 테스트")
    fun kisa_leaccm192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded, iv.iv)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded, iv.iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEAGCM-256 암복호화 테스트")
    fun kisa_leaccm256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded, iv.iv)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded, iv.iv))
        Assertions.assertEquals(message, originalMessage)
    }
}
