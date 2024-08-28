package dev.retrotv.crypto.encryption.block

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource

class LEATest {
    private val test = BlockChiperTest()

    @DisplayName("LEA 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}")
    @ValueSource(ints = [16, 24, 32])
    fun testLEA(keyLength: Int) {
        test.test_ecb(LEA(), keyLength)
    }

    @DisplayName("LEA - CBC 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    fun testCBC(keyLength: Int, ivLength: Int) {
        test.test_cbc(LEA(), keyLength, ivLength)
    }

    @DisplayName("LEA - OFB 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    fun testOFB(keyLength: Int, ivLength: Int) {
        test.test_ofb(LEA(), keyLength, ivLength)
    }

    @DisplayName("LEA - CFB 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    fun testCFB(keyLength: Int, ivLength: Int) {
        test.test_cfb(LEA(), keyLength, ivLength)
    }

    @DisplayName("LEA - CTR 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    fun testCTR(keyLength: Int, ivLength: Int) {
        test.test_ctr(LEA(), keyLength, ivLength)
    }

    @DisplayName("LEA - CTSECB 암호화 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "LEA keyLength: {0}")
    fun testCTSECB(keyLength: Int) {
        test.test_ctsecb(LEA(), keyLength)
    }

    @DisplayName("LEA - CTSCBC 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    fun testCTSCBC(keyLength: Int, ivLength: Int) {
        test.test_ctscbc(LEA(), keyLength, ivLength)
    }

    @DisplayName("LEA - CCM 암호화 테스트")
    @CsvSource("16,12", "24,12", "32,12")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    fun testCCM(keyLength: Int, ivLength: Int) {
        test.test_ccm(LEA(), keyLength, ivLength)
    }

    @DisplayName("LEA - GCM 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    fun testGCM(keyLength: Int, ivLength: Int) {
        test.test_gcm(LEA(), keyLength, ivLength)
    }
}