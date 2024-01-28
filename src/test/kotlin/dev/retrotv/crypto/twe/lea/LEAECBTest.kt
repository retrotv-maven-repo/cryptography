package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

internal class LEAECBTest {

    @Test
    @DisplayName("KISA LEAECB-128 암복호화 테스트")
    fun kisa_leaecb128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(128)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEAECB-192 암복호화 테스트")
    fun kisa_leaecb192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(192)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEAECB-256 암복호화 테스트")
    fun kisa_leaecb256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(256)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key.encoded)
        val originalMessage = String(lea.decrypt(encryptedData, key.encoded))
        Assertions.assertEquals(message, originalMessage)
    }
}
