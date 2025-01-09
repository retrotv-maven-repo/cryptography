package dev.retrotv.crypto.cipher.block

//import dev.retrotv.crypto.encryption.generator.generateIV
//import dev.retrotv.crypto.encryption.generator.generateKey
//import dev.retrotv.crypto.encryption.mode.CBC
//import dev.retrotv.crypto.encryption.mode.ECB
//import dev.retrotv.crypto.encryption.param.Params
//import dev.retrotv.crypto.encryption.param.ParamsWithIV
//import dev.retrotv.data.utils.ByteUtils
//import kr.re.nsr.crypto.BlockCipher.Mode.ENCRYPT
//import kr.re.nsr.crypto.engine.LeaEngine
//import kr.re.nsr.crypto.mode.CBCMode
//import kr.re.nsr.crypto.mode.ECBMode
//import kr.re.nsr.crypto.padding.PKCS5Padding
import dev.retrotv.crypto.cipher.block.algorithm.LEA
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
//import kotlin.test.assertEquals

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

    /*
    // KISA에서 제공하는 ARIAEngine과 동일하게 암호화 되는지 비교하기 위한 테스트 케이스 이므로 평소엔 제외할 것
    // 또한, build.gradle.ktsdml sourceSets를 주석처리해야 테스트 가능함
    @DisplayName("LEA - ECB BouncyCastle / KISA 비교 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "LEA keyLength: {0}")
    fun test_ecb_bc_kisa(keyLength: Int) {
        val plainText = "The quick brown fox jumps over the lazy dog"
        val kisaCipher = ECBMode(LeaEngine())
        val bcCipher = ECB(LEA())
        val key = generateKey(keyLength)

        kisaCipher.init(ENCRYPT, key)
        kisaCipher.setPadding(PKCS5Padding(16))
        val javaEncryptedData = kisaCipher.doFinal(plainText.toByteArray())
        val bcEncryptedData = bcCipher.encrypt(plainText.toByteArray(), Params(key))

        assertEquals(
            ByteUtils.toHexString(javaEncryptedData),
            ByteUtils.toHexString(bcEncryptedData.data)
        )
    }

    @DisplayName("LEA - CBC BouncyCastle / Java 비교 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "LEA keyLength: {0}")
    fun test_cbc_bc_kisa(keyLength: Int) {
        val plainText = "The quick brown fox jumps over the lazy dog"
        val kisaCipher = CBCMode(LeaEngine())
        val bcCipher = CBC(LEA())
        val key = generateKey(keyLength)
        val iv = generateIV(16)

        kisaCipher.init(ENCRYPT, key, iv)
        kisaCipher.setPadding(PKCS5Padding(16))
        val javaEncryptedData = kisaCipher.doFinal(plainText.toByteArray())
        val bcEncryptedData = bcCipher.encrypt(plainText.toByteArray(), ParamsWithIV(key, iv))

        assertEquals(
            ByteUtils.toHexString(javaEncryptedData),
            ByteUtils.toHexString(bcEncryptedData.data)
        )
    }
    */
}