package dev.retrotv.crypto.twe.lea

import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
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
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEAECB-192 암복호화 테스트")
    fun kisa_leaecb192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(192)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA LEAECB-256 암복호화 테스트")
    fun kisa_leaecb256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(256)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAECB-128 암복호화 테스트")
    fun bc_leaecb128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(128)
        val key = lea.generateKey()

        val encryptedData = encrypt(key.encoded, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAECB-192 암복호화 테스트")
    fun bc_leaecb192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(192)
        val key = lea.generateKey()

        val encryptedData = encrypt(key.encoded, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAECB-256 암복호화 테스트")
    fun bc_leaecb256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(256)
        val key = lea.generateKey()

        val encryptedData = encrypt(key.encoded, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    fun encrypt(key: ByteArray, plainText: ByteArray): ByteArray {

        // 블록보다 데이터가 짧을 경우 패딩을 사용함
        val cipher = PaddedBufferedBlockCipher(LEAEngine())

        // 초기화 및 키 파라미터 생성 첫 번째 매개변수가 true 라면 암호화 모드
        cipher.init(true, KeyParameter(key))

        val outputData = ByteArray(cipher.getOutputSize(plainText.size))
        val tam = cipher.processBytes(plainText, 0, plainText.size, outputData, 0)
        cipher.doFinal(outputData, tam)

        return outputData
    }

    fun decrypt(key: ByteArray, cipherText: ByteArray): ByteArray {
        val cipher = PaddedBufferedBlockCipher(LEAEngine())
        cipher.init(false, KeyParameter(key))

        val outputData = ByteArray(cipher.getOutputSize(cipherText.size))
        val tam = cipher.processBytes(cipherText, 0, cipherText.size, outputData, 0)
        val finalLen = cipher.doFinal(outputData, tam)
        val result = ByteArray(finalLen + tam)

        System.arraycopy(outputData, 0, result, 0, tam + finalLen)

        return result
    }
}
