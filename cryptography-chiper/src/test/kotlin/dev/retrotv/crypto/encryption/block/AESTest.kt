package dev.retrotv.crypto.encryption.block

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource

class AESTest {
    private val test = BlockChiperTest()

    @DisplayName("AES - ECB 암호화 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "AES keyLength: {0}")
    fun testECB(keyLength: Int) {
        test.test_ecb(AES(), keyLength)
    }

    @DisplayName("AES - CBC 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    fun testCBC(keyLength: Int, ivLength: Int) {
        test.test_cbc(AES(), keyLength, ivLength)
    }

    @DisplayName("AES - OFB 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    fun testOFB(keyLength: Int, ivLength: Int) {
        test.test_ofb(AES(), keyLength, ivLength)
    }

    @DisplayName("AES - CFB 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    fun testCFB(keyLength: Int, ivLength: Int) {
        test.test_cfb(AES(), keyLength, ivLength)
    }

    @DisplayName("AES - CTR 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    fun testCTR(keyLength: Int, ivLength: Int) {
        test.test_ctr(AES(), keyLength, ivLength)
    }

    @DisplayName("AES - CTSECB 암호화 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "AES keyLength: {0}")
    fun testCTSECB(keyLength: Int) {
        test.test_ctsecb(AES(), keyLength)
    }

    @DisplayName("AES - CTSCBC 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    fun testCTSCBC(keyLength: Int, ivLength: Int) {
        test.test_ctscbc(AES(), keyLength, ivLength)
    }
}