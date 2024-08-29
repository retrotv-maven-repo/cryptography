package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.encryption.block.algorithm.LEA
import dev.retrotv.crypto.encryption.block.algorithm.SEED
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource

class SEEDTest {
    private val test = BlockChiperTest()

    @DisplayName("SEED 암호화 테스트")
    @ValueSource(ints = [16])
    @ParameterizedTest(name = "SEED keyLength: {0}")
    fun testSEED(keyLength: Int) {
        test.test_ecb(SEED(), keyLength)
    }

    @DisplayName("SEED - CBC 암호화 테스트")
    @CsvSource("16,16")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    fun testCBC(keyLength: Int, ivLength: Int) {
        test.test_cbc(LEA(), keyLength, ivLength)
    }

    @DisplayName("SEED - OFB 암호화 테스트")
    @CsvSource("16,16")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    fun testOFB(keyLength: Int, ivLength: Int) {
        test.test_ofb(LEA(), keyLength, ivLength)
    }

    @DisplayName("SEED - CFB 암호화 테스트")
    @CsvSource("16,16")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    fun testCFB(keyLength: Int, ivLength: Int) {
        test.test_cfb(LEA(), keyLength, ivLength)
    }

    @DisplayName("SEED - CTR 암호화 테스트")
    @CsvSource("16,16")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    fun testCTR(keyLength: Int, ivLength: Int) {
        test.test_ctr(SEED(), keyLength, ivLength)
    }

    @DisplayName("SEED - CTSECB 암호화 테스트")
    @ValueSource(ints = [16])
    @ParameterizedTest(name = "SEED keyLength: {0}")
    fun testCTSECB(keyLength: Int) {
        test.test_ctsecb(SEED(), keyLength)
    }

    @DisplayName("SEED - CTSCBC 암호화 테스트")
    @CsvSource("16,16")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    fun testCTSCBC(keyLength: Int, ivLength: Int) {
        test.test_ctscbc(SEED(), keyLength, ivLength)
    }

    @DisplayName("SEED - CCM 암호화 테스트")
    @CsvSource("16,12")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    fun testCCM(keyLength: Int, ivLength: Int) {
        test.test_ccm(SEED(), keyLength, ivLength)
    }

    @DisplayName("SEED - GCM 암호화 테스트")
    @CsvSource("16,16")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    fun testGCM(keyLength: Int, ivLength: Int) {
        test.test_gcm(SEED(), keyLength, ivLength)
    }
}