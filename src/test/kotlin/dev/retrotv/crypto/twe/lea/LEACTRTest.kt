package dev.retrotv.crypto.twe.lea

import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CFBBlockCipher
import org.bouncycastle.crypto.modes.CTRModeCipher
import org.bouncycastle.crypto.modes.EAXBlockCipher
import org.bouncycastle.crypto.modes.G3413CTRBlockCipher
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class LEACTRTest {
    @Test
    @DisplayName("LEACTR-128 암복호화 테스트")
    fun leactr128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACTR(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACTR-192 암복호화 테스트")
    fun leactr192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACTR(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACTR-256 암복호화 테스트")
    fun leactr256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACTR(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    fun leactr() {
        val message = "The lazy dog jumps over the brown fox!".toByteArray()

        // 키의 길이는 16, 24, 32byte가 될수 있다
        val key = "0123456789012345".toByteArray()

        // iv 길이는 항상 16byte로 고정된다
        val iv = "0123456789012345".toByteArray()

        val encryptedData = encrypt(key, iv, message)
        val originalMessage = decrypt(key, iv, encryptedData)

        println(String(originalMessage))
    }

    fun encrypt(key: ByteArray, iv: ByteArray, plainText: ByteArray): ByteArray {
        val cipher = SICBlockCipher.newInstance(LEAEngine())
        cipher.init(true, ParametersWithIV(KeyParameter(key), iv))

        val outputData = ByteArray(plainText.size)
        cipher.processBytes(plainText, 0, plainText.size, outputData, 0)

        return outputData
    }

    fun decrypt(key: ByteArray, iv: ByteArray, cipherText: ByteArray): ByteArray {
        val cipher = SICBlockCipher.newInstance(LEAEngine())
        cipher.init(false, ParametersWithIV(KeyParameter(key), iv))

        val result = ByteArray(cipherText.size)
        cipher.processBytes(cipherText, 0, cipherText.size, result, 0)

        return result
    }
}
