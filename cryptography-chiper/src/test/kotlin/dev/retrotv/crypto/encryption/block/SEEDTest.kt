package dev.retrotv.crypto.encryption.block

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
}