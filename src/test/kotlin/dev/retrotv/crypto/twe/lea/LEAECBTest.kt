package dev.retrotv.crypto.twe.lea

import dev.retrotv.data.utils.hexStringToByteArray
import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal class LEAECBTest {
    @Test
    @DisplayName("LEAECB-128 암복호화 테스트")
    @Throws(Exception::class)
    fun leaecb128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(128)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAECB-192 암복호화 테스트")
    @Throws(Exception::class)
    fun leaecb192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(192)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEAECB-256 암복호화 테스트")
    @Throws(Exception::class)
    fun leaecb256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(256)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key)
        val originalMessage = String(lea.decrypt(encryptedData, key))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("KISA, Bouncy Castle 비교")
    fun leaecb_kisa_bc_test() {
        leaKisaBc(128)
        leaKisaBc(192)
        leaKisaBc(256)
    }

    private fun leaKisaBc(keySize: Int) {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEAECB(keySize)
        val key = lea.generateKey()
        lea.dataPadding()
        val encryptedData1 = lea.encrypt(message.toByteArray(), key, null)

        val ecb = PaddedBufferedBlockCipher(LEAEngine())
        ecb.init(true, KeyParameter(key.encoded))
        val encryptedData2 = ByteArray(ecb.getOutputSize(message.toByteArray().size))
        val bytesProcessed1: Int = ecb.processBytes(message.toByteArray(), 0, message.toByteArray().size, encryptedData2, 0)
        val bytesProcessed2: Int = ecb.doFinal(encryptedData2, bytesProcessed1)
        val result = ByteArray(bytesProcessed1 + bytesProcessed2)
        System.arraycopy(encryptedData2, 0, result, 0, result.size)

        Assertions.assertTrue(encryptedData1.contentEquals(encryptedData2))
    }

    @Test
    fun leaecb128() {
        val lea = LEACBC(128)

        val key = hexStringToByteArray("00000000000000000000000000000000")
        val iv = hexStringToByteArray("00000000000000000000000000000000")
        val data = hexStringToByteArray("E0000000000000000000000000000000")

        val encryptedData = lea.encrypt(data, SecretKeySpec(key, ""), IvParameterSpec(iv))
        println(toHexString(encryptedData))
    }
}
