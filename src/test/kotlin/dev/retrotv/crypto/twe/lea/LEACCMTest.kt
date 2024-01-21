package dev.retrotv.crypto.twe.lea

import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
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
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEAGCM-192 암복호화 테스트")
    fun kisa_leaccm192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEAGCM-256 암복호화 테스트")
    fun kisa_leaccm256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAGCM-128 암복호화 테스트")
    fun bc_leaccm128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()

        val encryptedData = encrypt(key.encoded, iv.iv, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, iv.iv, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAGCM-192 암복호화 테스트")
    fun bc_leaccm192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()

        val encryptedData = encrypt(key.encoded, iv.iv, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, iv.iv, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAGCM-256 암복호화 테스트")
    fun bc_leaccm256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()

        println(toHexString(iv.iv))

        val encryptedData = encrypt(key.encoded, iv.iv, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, iv.iv, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    fun leaccm() {
        val message = "The lazy dog jumps over the brown fox!".toByteArray()
        val key = "0123456789012345".toByteArray()
        val iv = "012345678901".toByteArray()

        val encryptedData = encrypt(key, iv, message)
        val originalMessage = decrypt(key, iv, encryptedData)

        println(String(originalMessage))
    }

    fun encrypt(key: ByteArray, iv: ByteArray, plainText: ByteArray): ByteArray {
        val cipher = CCMBlockCipher.newInstance(LEAEngine())
        cipher.init(true, ParametersWithIV(KeyParameter(key), iv))

        println(toHexString(cipher.mac))

        val outputData = ByteArray(cipher.getOutputSize(plainText.size))
        val tam = cipher.processBytes(plainText, 0, plainText.size, outputData, 0)
        cipher.doFinal(outputData, tam)

        return outputData
    }

    fun decrypt(key: ByteArray, iv: ByteArray, cipherText: ByteArray): ByteArray {
        val cipher = CCMBlockCipher.newInstance(LEAEngine())
        cipher.init(false, ParametersWithIV(KeyParameter(key), iv))

        val outputData = ByteArray(cipher.getOutputSize(cipherText.size))
        val tam = cipher.processBytes(cipherText, 0, cipherText.size, outputData, 0)
        val finalLen = cipher.doFinal(outputData, tam)
        val result = ByteArray(finalLen + tam)

        System.arraycopy(outputData, 0, result, 0, tam + finalLen)

        return result
    }
}
