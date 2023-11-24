package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import javax.crypto.spec.GCMParameterSpec

internal class LEACCMTest {
    @Test
    @DisplayName("LEAGCM-128 암복호화 테스트")
    @Throws(Exception::class)
    fun leagcm128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(128)
        val key = lea.generateKey()
        val iv: GCMParameterSpec = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAGCM-192 암복호화 테스트")
    @Throws(Exception::class)
    fun leagcm192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(192)
        val key = lea.generateKey()
        val iv: GCMParameterSpec = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAGCM-256 암복호화 테스트")
    @Throws(Exception::class)
    fun leagcm256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(256)
        val key = lea.generateKey()
        val iv: GCMParameterSpec = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }
}
