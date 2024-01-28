package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.exception.CryptoFailException
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
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
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAGCM-192 암복호화 테스트")
    fun leagcm192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAGCM(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAGCM-256 암복호화 테스트")
    fun leagcm256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAGCM(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    fun leagcm() {
        val message = "The lazy dog jumps over the brown fox!".toByteArray()
        val key = "0123456789012345".toByteArray()

        // GCM 모드의 iv는 1 ~ 2^64byte의 값이다 (보통 12byte를 사용)
        val iv = "012345678901".toByteArray()

        // 추가 인증 데이터, 만약 암호화/복호화 시 사용한 값이 서로 다르면 정상적으로 암복호화 되지 않는다 (선택사항)
        val aad = "0123456789012345".toByteArray()

        val encryptedData = encrypt(key, iv, message, aad)
        val originalMessage = decrypt(key, iv, encryptedData, aad)

        println(String(originalMessage))
    }

    @Throws(CryptoFailException::class)
    fun encrypt(key: ByteArray, iv: ByteArray, plainText: ByteArray, aad: ByteArray? = null): ByteArray {
        val macSize = 128
        val cipher = GCMBlockCipher.newInstance(LEAEngine())
            cipher.init(true, AEADParameters(KeyParameter(key), macSize, iv, aad))

        if (aad != null) {
            cipher.processAADBytes(aad, 0, aad.size)
        }

        val outputData = ByteArray(cipher.getOutputSize(plainText.size))
        var tam = cipher.processBytes(plainText, 0, plainText.size, outputData, 0)

        try {
            tam += cipher.doFinal(outputData, tam)
        } catch (e: InvalidCipherTextException) {
            throw CryptoFailException("GCM 인증 태그를 생성 실패: " + e.message, e)
        }

        val encryptedData = ByteArray(tam - (macSize / 8))
        val authTag = ByteArray(macSize / 8)

        System.arraycopy(outputData, 0, encryptedData, 0, encryptedData.size)
        System.arraycopy(outputData, tam - (macSize / 8), authTag, 0, macSize / 8)

        return outputData
    }

    @Throws(CryptoFailException::class)
    fun decrypt(key: ByteArray, iv: ByteArray, cipherText: ByteArray, aad: ByteArray? = null): ByteArray {
        val macSize = 128
        val cipher = GCMBlockCipher.newInstance(LEAEngine())
        cipher.init(false, AEADParameters(KeyParameter(key), macSize, iv, aad))

        if (aad != null) {
            cipher.processAADBytes(aad, 0, aad.size)
        }

        val outputData = ByteArray(cipher.getOutputSize(cipherText.size))
        var tam = cipher.processBytes(cipherText, 0, cipherText.size, outputData, 0)

        try {
            tam += cipher.doFinal(outputData, tam)
        } catch (e: InvalidCipherTextException) {
            throw CryptoFailException("GCM 인증 태그를 생성 실패: " + e.message, e)
        }

        return outputData
    }
}
