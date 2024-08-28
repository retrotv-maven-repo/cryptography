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
}