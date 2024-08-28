package dev.retrotv.crypto.encryption.block

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
}