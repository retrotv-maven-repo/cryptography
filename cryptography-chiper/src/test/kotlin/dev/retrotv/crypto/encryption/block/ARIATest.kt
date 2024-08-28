package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.encryption.generator.generateKey
import dev.retrotv.crypto.encryption.mode.ECB
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.data.utils.ByteUtils
import kr.re.nsri.aria.engine.ARIAEngine
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertEquals

class ARIATest {
    private val test = BlockChiperTest()

    @DisplayName("ARIA - ECB 암호화 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "ARIA keyLength: {0}")
    fun testECB(keyLength: Int) {
        test.test_ecb(ARIA(), keyLength)
    }

    @DisplayName("ARIA - CBC 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testCBC(keyLength: Int, ivLength: Int) {
        test.test_cbc(ARIA(), keyLength, ivLength)
    }

    @DisplayName("ARIA - OFB 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testOFB(keyLength: Int, ivLength: Int) {
        test.test_ofb(ARIA(), keyLength, ivLength)
    }

    @DisplayName("ARIA - CFB 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testCFB(keyLength: Int, ivLength: Int) {
        test.test_cfb(ARIA(), keyLength, ivLength)
    }

    @DisplayName("ARIA - CTR 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testCTR(keyLength: Int, ivLength: Int) {
        test.test_ctr(ARIA(), keyLength, ivLength)
    }

    @DisplayName("ARIA - CTSECB 암호화 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "ARIA keyLength: {0}")
    fun testCTSECB(keyLength: Int) {
        test.test_ctsecb(ARIA(), keyLength)
    }

    @DisplayName("ARIA - CTSCBC 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testCTSCBC(keyLength: Int, ivLength: Int) {
        test.test_ctscbc(ARIA(), keyLength, ivLength)
    }

    @DisplayName("ARIA - CCM 암호화 테스트")
    @CsvSource("16,12", "24,12", "32,12")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testCCM(keyLength: Int, ivLength: Int) {
        test.test_ccm(ARIA(), keyLength, ivLength)
    }

    @DisplayName("ARIA - GCM 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testGCM(keyLength: Int, ivLength: Int) {
        test.test_gcm(ARIA(), keyLength, ivLength)
    }

    /*
    // KISA에서 제공하는 ARIAEngine과 동일하게 암호화 되는지 비교하기 위한 테스트 케이스 이므로 평소엔 제외할 것
    // 또한, build.gradle.ktsdml sourceSets를 주석처리해야 테스트 가능함
    @DisplayName("ARIA - ECB BouncyCastle / KISA 비교 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "ARIA keyLength: {0}")
    fun test_ecb_bc_java(keyLength: Int) {
        val plainText = "0123456789abcde"
        val kisaCipher = ARIAEngine(keyLength * 8)
        val bcCipher = ECB(ARIA())
        val key = generateKey(keyLength)

        val kisaEncryptedData =  kisaCipher.encrypt(plainText.toByteArray(), key)
        val bcEncryptedData = bcCipher.encrypt(plainText.toByteArray(), Params(key))

        assertEquals(
            ByteUtils.toHexString(kisaEncryptedData),
            ByteUtils.toHexString(bcEncryptedData.data)
        )
    }
    */
}