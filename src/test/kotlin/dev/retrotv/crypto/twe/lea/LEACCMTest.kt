package dev.retrotv.crypto.twe.lea

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.Test

internal class LEACCMTest {

    @Test
    @DisplayName("LEAGCM-128 암복호화 테스트")
    fun leaccm128_test() {
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
    fun leaccm192_test() {
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
    fun leaccm256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACCM(256)
        val key = lea.generateKey()
        val iv: GCMParameterSpec = lea.generateSpec()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("Bouncy Castle로 LEACCM 암호화")
    fun leaccm_BouncyCastle_test() {

    }

//    @Test
//    @DisplayName("KISA, Bouncy Castle 비교")
//    fun leaccm_kisa_bc_test() {
//        leaKisaBc(128)
//        leaKisaBc(192)
//        leaKisaBc(256)
//    }
//
//    private fun leaKisaBc(keySize: Int) {
//        val message = "The lazy dog jumps over the brown fox!"
//        val lea = LEACCM(keySize)
//        val key = lea.generateKey()
//        val iv = lea.generateSpec()
//        val encryptedData1 = lea.encrypt(message.toByteArray(), key, iv)
//
//        val ccm = CCMBlockCipher.newInstance(LEAEngine())
//        ccm.init(true, ParametersWithIV(KeyParameter(key.encoded), iv.iv))
//        val encryptedData2 = ByteArray(ccm.getOutputSize(message.toByteArray().size))
//        val bytesProcessed1 = ccm.processBytes(message.toByteArray(), 0, message.toByteArray().size, encryptedData2, 0)
//        val bytesProcessed2 = ccm.doFinal(encryptedData2, bytesProcessed1)
//        val result = ByteArray(bytesProcessed1 + bytesProcessed2)
//        System.arraycopy(encryptedData2, 0, result, 0, result.size)
//
//        println(toHexString(encryptedData1))
//        println(toHexString(encryptedData2))
//        Assertions.assertTrue(encryptedData1.contentEquals(encryptedData2))
//    }
}
