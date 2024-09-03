package dev.retrotv.crypto.encryption.block

//import dev.retrotv.crypto.encryption.generator.generateIV
//import dev.retrotv.crypto.encryption.generator.generateKey
//import dev.retrotv.crypto.encryption.mode.CBC
//import dev.retrotv.crypto.encryption.mode.ECB
//import dev.retrotv.crypto.encryption.param.Params
//import dev.retrotv.crypto.encryption.param.ParamsWithIV
//import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.crypto.encryption.block.algorithm.AES
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
//import javax.crypto.Cipher
//import javax.crypto.spec.IvParameterSpec
//import javax.crypto.spec.SecretKeySpec
//import kotlin.test.assertEquals

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

    @DisplayName("AES - CCM 암호화 테스트")
    @CsvSource("16,12", "24,12", "32,12")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    fun testCCM(keyLength: Int, ivLength: Int) {
        test.test_ccm(AES(), keyLength, ivLength)
    }

    @DisplayName("AES - GCM 암호화 테스트")
    @CsvSource("16,16", "24,16", "32,16")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    fun testGCM(keyLength: Int, ivLength: Int) {
        test.test_gcm(AES(), keyLength, ivLength)
    }

    /*
    // JAVA에서 제공하는 Cipher와 동일하게 암호화 되는지 비교하기 위한 테스트 케이스 이므로 평소엔 제외할 것
    @DisplayName("AES - ECB BouncyCastle / Java 비교 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "AES keyLength: {0}")
    fun test_ecb_bc_java(keyLength: Int) {
        val plainText = "The quick brown fox jumps over the lazy dog"
        val javaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val bcCipher = ECB(AES())
        val key = generateKey(keyLength)

        javaCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val javaEncryptedData = javaCipher.doFinal(plainText.toByteArray())
        val bcEncryptedData = bcCipher.encrypt(plainText.toByteArray(), Params(key))

        assertEquals(
            ByteUtils.toHexString(javaEncryptedData),
            ByteUtils.toHexString(bcEncryptedData.data)
        )
    }

    @DisplayName("AES - CBC BouncyCastle / Java 비교 테스트")
    @ValueSource(ints = [16, 24, 32])
    @ParameterizedTest(name = "AES keyLength: {0}")
    fun test_cbc_bc_java(keyLength: Int) {
        val plainText = "The quick brown fox jumps over the lazy dog"
        val javaCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val bcCipher = CBC(AES())
        val key = generateKey(keyLength)
        val iv = generateIV(16)

        javaCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        val javaEncryptedData = javaCipher.doFinal(plainText.toByteArray())
        val bcEncryptedData = bcCipher.encrypt(plainText.toByteArray(), ParamsWithIV(key, iv))

        assertEquals(
            ByteUtils.toHexString(javaEncryptedData),
            ByteUtils.toHexString(bcEncryptedData.data)
        )
    }
    */
}