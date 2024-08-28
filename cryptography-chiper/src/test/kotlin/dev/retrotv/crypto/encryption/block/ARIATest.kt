package dev.retrotv.crypto.encryption.block

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource

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
}