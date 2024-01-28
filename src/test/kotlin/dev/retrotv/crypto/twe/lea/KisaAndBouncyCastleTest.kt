package dev.retrotv.crypto.twe.lea

import dev.retrotv.data.utils.toHexString
import kr.re.nsr.crypto.mode.CCMMode
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.modes.CFBBlockCipher
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.modes.OFBBlockCipher
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.assertEquals

class KisaAndBouncyCastleTest {

//    private val MESSAGE = "The lazy dog jumps over the brown fox!"
//
//    @Test
//    @DisplayName("ECB-128 테스트")
//    fun test_ecb128() {
//        val lea = LEAECB(128)
//        val key = lea.generateKey()
//            lea.dataPadding()
//
//        val encryptedData1 = lea.encrypt(MESSAGE.toByteArray(), key)
//
//        val lea2 = PaddedBufferedBlockCipher(LEAEngine())
//        lea2.init(true, KeyParameter(key.encoded))
//
//        val encryptedData2 = ByteArray(lea2.getOutputSize(MESSAGE.toByteArray().size))
//        val tam = lea2.processBytes(MESSAGE.toByteArray(), 0, MESSAGE.toByteArray().size, encryptedData2, 0)
//            lea2.doFinal(encryptedData2, tam)
//
//        println(toHexString(encryptedData1))
//        println(toHexString(encryptedData2))
//
//        assertEquals(toHexString(encryptedData1), toHexString(encryptedData2))
//    }
//
//    @Test
//    @DisplayName("CBC-128 테스트")
//    fun test_cbc128() {
//        val lea = LEACBC(128)
//        val key = lea.generateKey()
//        val iv = lea.generateSpec()
//            lea.dataPadding()
//
//        val encryptedData1 = lea.encrypt(MESSAGE.toByteArray(), key, iv)
//
//        val lea2 = PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(LEAEngine()))
//        lea2.init(true, ParametersWithIV(KeyParameter(key.encoded), iv.iv))
//
//        val encryptedData2 = ByteArray(lea2.getOutputSize(MESSAGE.toByteArray().size))
//        val tam = lea2.processBytes(MESSAGE.toByteArray(), 0, MESSAGE.toByteArray().size, encryptedData2, 0)
//        lea2.doFinal(encryptedData2, tam)
//
//        println(toHexString(encryptedData1))
//        println(toHexString(encryptedData2))
//
//        assertEquals(toHexString(encryptedData1), toHexString(encryptedData2))
//    }
//
//    @Test
//    @DisplayName("CFB-128 테스트")
//    fun test_cfb128() {
//        val lea = LEACFB(128)
//        val key = lea.generateKey()
//        val iv = lea.generateSpec()
//
//        val encryptedData1 = lea.encrypt(MESSAGE.toByteArray(), key, iv)
//
//        val lea2 = CFBBlockCipher.newInstance(LEAEngine(), 128)
//        lea2.init(true, ParametersWithIV(KeyParameter(key.encoded), iv.iv))
//
//        val encryptedData2 = ByteArray(MESSAGE.toByteArray().size)
//        lea2.processBytes(MESSAGE.toByteArray(), 0, MESSAGE.toByteArray().size, encryptedData2, 0)
//
//        println(toHexString(encryptedData1))
//        println(toHexString(encryptedData2))
//
//        assertEquals(toHexString(encryptedData1), toHexString(encryptedData2))
//    }
//
//    @Test
//    @DisplayName("OFB-128 테스트")
//    fun test_ofb128() {
//        val lea = LEAOFB(128)
//        val key = lea.generateKey()
//        val iv = lea.generateSpec()
//            lea.dataPadding()
//
//        val encryptedData1 = lea.encrypt(MESSAGE.toByteArray(), key, iv)
//
//        val lea2 = OFBBlockCipher(LEAEngine(), 128)
//        lea2.init(true, ParametersWithIV(KeyParameter(key.encoded), iv.iv))
//
//        val encryptedData2 = ByteArray(MESSAGE.toByteArray().size)
//        val tam = lea2.processBytes(MESSAGE.toByteArray(), 0, MESSAGE.toByteArray().size, encryptedData2, 0)
//
//        println(toHexString(encryptedData1))
//        println(toHexString(encryptedData2))
//
//        assertEquals(toHexString(encryptedData1), toHexString(encryptedData2))
//    }
//
//    @Test
//    @DisplayName("CTR-128 테스트")
//    fun test_ctr128() {
//        val lea = LEACTR(128)
//        val key = lea.generateKey()
//        val iv = lea.generateSpec()
//
//        val encryptedData1 = lea.encrypt(MESSAGE.toByteArray(), key, iv)
//
//        val lea2 = SICBlockCipher.newInstance(LEAEngine())
//        lea2.init(true, ParametersWithIV(KeyParameter(key.encoded), iv.iv))
//
//        val encryptedData2 = ByteArray(MESSAGE.toByteArray().size)
//        val tam = lea2.processBytes(MESSAGE.toByteArray(), 0, MESSAGE.toByteArray().size, encryptedData2, 0)
//
//        println(toHexString(encryptedData1))
//        println(toHexString(encryptedData2))
//
//        assertEquals(toHexString(encryptedData1), toHexString(encryptedData2))
//    }
//
//    @Test
//    @DisplayName("CCM-128 테스트")
//    fun test_ccm128() {
//        val lea = LEACCM(128)
//        val key = lea.generateKey()
//        val iv = lea.generateSpec()
//        val aad = "0123456789012345"
//
//        lea.updateAAD(aad)
//        val encryptedData1 = lea.encrypt(MESSAGE.toByteArray(), key, iv)
//
//        val lea2 = CCMBlockCipher.newInstance(LEAEngine())
//        lea2.init(true, AEADParameters(KeyParameter(key.encoded), 128, iv.iv, aad.toByteArray()))
//
//        val encryptedData2 = ByteArray(lea2.getOutputSize(MESSAGE.toByteArray().size))
//        var tam = lea2.processBytes(MESSAGE.toByteArray(), 0, MESSAGE.toByteArray().size, encryptedData2, 0)
//            tam += lea2.doFinal(encryptedData2, tam)
//
//        println(toHexString(encryptedData1))
//        println(toHexString(encryptedData2))
//
//        assertEquals(toHexString(encryptedData1), toHexString(encryptedData2))
//    }
//
//    @Test
//    @DisplayName("GCM-128 테스트")
//    fun test_gcm128() {
//        val lea = LEAGCM(128)
//        val key = lea.generateKey()
//        val iv = lea.generateSpec()
//        val aad = "0123456789012345"
//
//        lea.updateAAD(aad)
//        val encryptedData1 = lea.encrypt(MESSAGE.toByteArray(), key, iv)
//
//        val lea2 = GCMBlockCipher.newInstance(LEAEngine())
//        lea2.init(true, AEADParameters(KeyParameter(key.encoded), 128, iv.iv, aad.toByteArray()))
//        lea2.processAADBytes(aad.toByteArray(), 0, aad.toByteArray().size)
//
//        val encryptedData2 = ByteArray(lea2.getOutputSize(MESSAGE.toByteArray().size))
//        var tam = lea2.processBytes(MESSAGE.toByteArray(), 0, MESSAGE.toByteArray().size, encryptedData2, 0)
//        tam += lea2.doFinal(encryptedData2, tam)
//
//        println(toHexString(encryptedData1))
//        println(toHexString(encryptedData2))
//
//        assertEquals(toHexString(encryptedData1), toHexString(encryptedData2))
//    }
}