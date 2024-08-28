package dev.retrotv.crypto.encryption.block

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import sun.security.util.Length

class DESTest {
    private val test = BlockChiperTest()

    @DisplayName("DES - ECB 암호화 테스트")
    @ValueSource(ints = [8])
    @ParameterizedTest(name = "DES keyLength: {0}")
    fun testECB(keyLength: Int) {
        test.test_ecb(DES(), keyLength)
    }

    @DisplayName("DES - CBC 암호화 테스트")
    @CsvSource("8,8")
    @ParameterizedTest(name = "DES keyLength: {0}, ivLength: {1}")
    fun testCBC(keyLength: Int, ivLength: Int) {
        test.test_cbc(DES(), keyLength, ivLength)
    }

    @DisplayName("DES - OFB 암호화 테스트")
    @CsvSource("8,8")
    @ParameterizedTest(name = "DES keyLength: {0}, ivLength: {1}")
    fun testOFB(keyLength: Int, ivLength: Int) {
        test.test_ofb(DES(), keyLength, ivLength)
    }

    @DisplayName("DES - CFB 암호화 테스트")
    @CsvSource("8,8")
    @ParameterizedTest(name = "DES keyLength: {0}, ivLength: {1}")
    fun testCFB(keyLength: Int, ivLength: Int) {
        test.test_cfb(DES(), keyLength, ivLength)
    }
}