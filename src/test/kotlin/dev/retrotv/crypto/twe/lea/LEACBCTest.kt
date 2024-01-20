package dev.retrotv.crypto.twe.lea

import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


internal class LEACBCTest {
    @Test
    @DisplayName("LEACBC-128 암복호화 테스트")
    fun leacbc128_test() {
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
    fun leacbc192_test() {
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
    fun leacbc256_test() {
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
    @DisplayName("KISA, Bouncy Castle 비교")
    fun leacbc128_kisa_bc_test() {
        leaKisaBc(128)
        leaKisaBc(192)
        leaKisaBc(256)
    }

    private fun leaKisaBc(keySize: Int) {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(keySize)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData1 = lea.encrypt(message.toByteArray(), key, iv)

        val cbc = PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(LEAEngine()), PKCS7Padding())
        cbc.init(true, ParametersWithIV(KeyParameter(key.encoded), iv.iv))
        val encryptedData2 = ByteArray(cbc.getOutputSize(message.toByteArray().size))
        val bytesProcessed1: Int = cbc.processBytes(message.toByteArray(), 0, message.toByteArray().size, encryptedData2, 0)
        val bytesProcessed2: Int = cbc.doFinal(encryptedData2, bytesProcessed1)
        val result = ByteArray(bytesProcessed1 + bytesProcessed2)
        System.arraycopy(encryptedData2, 0, result, 0, result.size)

        Assertions.assertTrue(encryptedData1.contentEquals(encryptedData2))
    }
}
