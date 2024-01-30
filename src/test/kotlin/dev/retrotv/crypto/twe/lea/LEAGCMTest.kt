package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class LEAGCMTest {

    @Test
    @DisplayName("LEAGCM-128 암복호화 테스트")
    fun leagcm128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAGCM(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val aad = "0123456789012345".toByteArray()
        val params = ParamsWithIV(key.encoded, iv.iv)

            lea.updateAAD(aad)

        val encryptedData = lea.encrypt(message.toByteArray(), params) as AEADResult
        val originalMessage = String(lea.decrypt(encryptedData.data + encryptedData.tag, params).data)
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAGCM-192 암복호화 테스트")
    fun leagcm192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAGCM(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val aad = "0123456789012345".toByteArray()
        val params = ParamsWithIV(key.encoded, iv.iv)

            lea.updateAAD(aad)

        val encryptedData = lea.encrypt(message.toByteArray(), params) as AEADResult
        val originalMessage = String(lea.decrypt(encryptedData.data + encryptedData.tag, params).data)
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAGCM-256 암복호화 테스트")
    fun leagcm256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAGCM(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val aad = "0123456789012345".toByteArray()
        val params = ParamsWithIV(key.encoded, iv.iv)

        lea.updateAAD(aad)

        val encryptedData = lea.encrypt(message.toByteArray(), params) as AEADResult
        val originalMessage = String(lea.decrypt(encryptedData.data + encryptedData.tag, params).data)
        Assertions.assertEquals(message, originalMessage)
    }
}
