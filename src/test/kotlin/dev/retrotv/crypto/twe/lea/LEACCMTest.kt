package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

internal class LEACCMTest {

    @Test
    @DisplayName("KISA LEACCM-128 암복호화 테스트")
    fun kisa_leaccm128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val aad = "0123456789012345".toByteArray()
        val params = ParamsWithIV(key.encoded, iv.iv)

            lea.updateAAD(aad)

        val encryptedData = lea.encrypt(message.toByteArray(), params)
        val originalMessage = String(lea.decrypt(encryptedData.data, params).data)
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEACCM-192 암복호화 테스트")
    fun kisa_leaccm192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val aad = "0123456789012345".toByteArray()
        val params = ParamsWithIV(key.encoded, iv.iv)

            lea.updateAAD(aad)

        val encryptedData = lea.encrypt(message.toByteArray(), params)
        val originalMessage = String(lea.decrypt(encryptedData.data, params).data)
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEACCM-256 암복호화 테스트")
    fun kisa_leaccm256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val aad = "0123456789012345".toByteArray()
        val params = ParamsWithIV(key.encoded, iv.iv)

            lea.updateAAD(aad)

        val encryptedData = lea.encrypt(message.toByteArray(), params)
        val originalMessage = String(lea.decrypt(encryptedData.data, params).data)
        Assertions.assertEquals(message, originalMessage)
    }
}
