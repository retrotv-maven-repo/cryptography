package dev.retrotv.crypto.cipher.block

import dev.retrotv.crypto.cipher.block.algorithm.ARIA
import dev.retrotv.crypto.cipher.block.algorithm.TripleDES
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource

class TripleDESTest {
    private val test = BlockChiperTest()

    @DisplayName("TripleDES 암호화 테스트")
    @ParameterizedTest(name = "TripleDES keyLength: {0}")
    @ValueSource(ints = [16, 24])
    fun testTripleDES(keyLength: Int) {
        test.test_ecb(TripleDES(), keyLength)
    }

    @DisplayName("TripleDES - CBC 암호화 테스트")
    @CsvSource("16,8", "24,8")
    @ParameterizedTest(name = "TripleDES keyLength: {0}, ivLength: {1}")
    fun testCBC(keyLength: Int, ivLength: Int) {
        test.test_cbc(TripleDES(), keyLength, ivLength)
    }

    @DisplayName("TripleDES - OFB 암호화 테스트")
    @CsvSource("16,8", "24,8")
    @ParameterizedTest(name = "TripleDES keyLength: {0}, ivLength: {1}")
    fun testOFB(keyLength: Int, ivLength: Int) {
        test.test_ofb(TripleDES(), keyLength, ivLength)
    }

    @DisplayName("TripleDES - CFB 암호화 테스트")
    @CsvSource("16,8", "24,8")
    @ParameterizedTest(name = "TripleDES keyLength: {0}, ivLength: {1}")
    fun testCFB(keyLength: Int, ivLength: Int) {
        test.test_cfb(TripleDES(), keyLength, ivLength)
    }

    @DisplayName("ARIA - CTR 암호화 테스트")
    @CsvSource("16,8", "24,8")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testCTR(keyLength: Int, ivLength: Int) {
        test.test_ctr(ARIA(), keyLength, ivLength)
    }

    @DisplayName("ARIA - CTSECB 암호화 테스트")
    @ValueSource(ints = [16, 24])
    @ParameterizedTest(name = "ARIA keyLength: {0}")
    fun testCTSECB(keyLength: Int) {
        test.test_ctsecb(ARIA(), keyLength)
    }

    @DisplayName("ARIA - CTSCBC 암호화 테스트")
    @CsvSource("16,16", "24,16")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    fun testCTSCBC(keyLength: Int, ivLength: Int) {
        test.test_ctscbc(ARIA(), keyLength, ivLength)
    }
}