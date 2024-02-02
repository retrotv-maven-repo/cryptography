package dev.retrotv.crypto.twe.lea

import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
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

    @Test
    @DisplayName("KISA, BC 비교")
    fun kisa_bc_test() {
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

        println(toHexString(encryptedData.data))

        val cipher = CCMBlockCipher.newInstance(LEAEngine())
            cipher.init(true, AEADParameters(KeyParameter(key.encoded), 128, iv.iv, aad))

        val outputData = ByteArray(cipher.getOutputSize(message.toByteArray().size))
        var tam = cipher.processBytes(message.toByteArray(), 0, message.toByteArray().size, outputData, 0)
            tam += cipher.doFinal(outputData, tam)

        println(toHexString(outputData))
        println(toHexString(cipher.mac))
    }
}
