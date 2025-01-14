package dev.retrotv.crypto.cipher.block

import dev.retrotv.crypto.cipher.block.algorithm.Serpent
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource

class SerpentTest {
    private val test = BlockChiperTest()

    @DisplayName("Serpent 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}")
    @ValueSource(ints = [16, 24, 32])
    fun testSerpent(keyLength: Int) {
        test.test_ecb(Serpent(), keyLength)
    }

    @DisplayName("Serpent - CBC 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    fun testCBC(keyLength: Int, ivLength: Int) {
        test.test_cbc(Serpent(), keyLength, ivLength)
    }

    @DisplayName("Serpent - OFB 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    fun testOFB(keyLength: Int, ivLength: Int) {
        test.test_ofb(Serpent(), keyLength, ivLength)
    }

    @DisplayName("Serpent - CFB 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    fun testCFB(keyLength: Int, ivLength: Int) {
        test.test_cfb(Serpent(), keyLength, ivLength)
    }

    @DisplayName("Serpent - CTR 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    fun testCTR(keyLength: Int, ivLength: Int) {
        test.test_ctr(Serpent(), keyLength, ivLength)
    }

    @DisplayName("Serpent - CTSECB 암호화 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "Serpent keyLength: {0}")
    fun testCTSECB(keyLength: Int) {
        test.test_ctsecb(Serpent(), keyLength)
    }

    @DisplayName("Serpent - CTSCBC 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    fun testCTSCBC(keyLength: Int, ivLength: Int) {
        test.test_ctscbc(Serpent(), keyLength, ivLength)
    }

    @DisplayName("Serpent - CCM 암호화 테스트")
    @CsvSource("16,12", "24,12", "32,12")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    fun testCCM(keyLength: Int, ivLength: Int) {
        test.test_ccm(Serpent(), keyLength, ivLength)
    }

    @DisplayName("Serpent - GCM 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    fun testGCM(keyLength: Int, ivLength: Int) {
        test.test_gcm(Serpent(), keyLength, ivLength)
    }
}