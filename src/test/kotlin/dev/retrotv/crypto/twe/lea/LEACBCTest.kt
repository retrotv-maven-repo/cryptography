package dev.retrotv.crypto.twe.lea

import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
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
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
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
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
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
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAECB-128 암복호화 테스트")
    fun bc_leaecb128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()

        val encryptedData = encrypt(key.encoded, iv.iv, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, iv.iv, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAECB-192 암복호화 테스트")
    fun bc_leaecb192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()

        val encryptedData = encrypt(key.encoded, iv.iv, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, iv.iv, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle LEAECB-256 암복호화 테스트")
    fun bc_leaecb256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()

        val encryptedData = encrypt(key.encoded, iv.iv, message.toByteArray())
        val originalMessage = String(decrypt(key.encoded, iv.iv, encryptedData))
        Assertions.assertEquals(message, originalMessage)
    }

    fun encrypt(key: ByteArray, iv: ByteArray, plainText: ByteArray): ByteArray {

        // 블록보다 데이터가 짧을 경우 패딩을 사용함
        val cipher: BufferedBlockCipher = PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(LEAEngine()))

        // 초기화 및 키 파라미터 생성 첫 번째 매개변수가 true 라면 암호화 모드
        cipher.init(true, ParametersWithIV(KeyParameter(key), iv))

        val outputData = ByteArray(cipher.getOutputSize(plainText.size))
        val tam = cipher.processBytes(plainText, 0, plainText.size, outputData, 0)
        cipher.doFinal(outputData, tam)

        return outputData
    }

    fun decrypt(key: ByteArray, iv: ByteArray, cipherText: ByteArray): ByteArray {
        val cipher: BufferedBlockCipher = PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(LEAEngine()))
        cipher.init(false, ParametersWithIV(KeyParameter(key), iv))

        val outputData = ByteArray(cipher.getOutputSize(cipherText.size))
        val tam = cipher.processBytes(cipherText, 0, cipherText.size, outputData, 0)
        val finalLen = cipher.doFinal(outputData, tam)
        val result = ByteArray(finalLen + tam)

        System.arraycopy(outputData, 0, result, 0, tam + finalLen)

        return result
    }
}
