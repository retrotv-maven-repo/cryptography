package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.twe.AEADResult
import dev.retrotv.crypto.twe.CipherAlgorithm
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.AES
import dev.retrotv.crypto.twe.mode.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.Test
import kotlin.test.asserter

class AESTest {
    private val message = "The lazy dog jumps over the brown fox!".toByteArray()
    private lateinit var aes: CipherAlgorithm

    @DisplayName("ECB 모드 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ecb(keyLen: Int) {
        this.aes = AES(keyLen)
        val key = aes.generateKey()
        val mode = ECB(aes)
        val encryptedData = mode.encrypt(message, Params(key))
        val originalData = mode.decrypt(encryptedData.data, Params(key))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CBC 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cbc(keyLen: Int) {
        this.aes = AES(keyLen)
        val key = aes.generateKey()
        val mode = CBC(aes)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CFB 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cfb(keyLen: Int) {
        this.aes = AES(keyLen)
        val key = aes.generateKey()
        val mode = CFB(aes)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("OFB 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ofb(keyLen: Int) {
        this.aes = AES(keyLen)
        val key = aes.generateKey()
        val mode = OFB(aes)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CTR 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ctr(keyLen: Int) {
        this.aes = AES(keyLen)
        val key = aes.generateKey()
        val mode = CTR(aes)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CTS 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cts(keyLen: Int) {

        /*
         * CTS 모드는 엔진을 CBCBlockCipher.newInstance()로 감싸서 사용할 수 있다.
         * 이 때, CBC 모드로 패딩한다면 key + iv 값이 필요하며, EBS 모드만 사용하면 key 값만 있으면 된다.
         * 또한, 블록 사이즈 보다 데이터 크기가 작으면 사용할 수 없다. 이 경우에는 iv 값을 데이터 끝에 패딩하는 식으로 사용해야 한다.
         */

        this.aes = AES(keyLen)
        val key = aes.generateKey()
        val mode = CTS(aes)
        val iv = mode.generateIV()
        mode.useCBCMode()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CCM 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ccm(keyLen: Int) {
        this.aes = AES(keyLen)
        val key = aes.generateKey()
        val mode = CCM(aes)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("GCM 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_gcm(keyLen: Int) {
        this.aes = AES(keyLen)
        val key = aes.generateKey()
        val mode = GCM(aes)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv)) as AEADResult
        val originalData = mode.decrypt(encryptedData.data + encryptedData.tag, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    fun test_default() {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AES(128)
        val cbc = CBC(aes)
        val iv = cbc.generateIV()
        val key = aes.generateKey()

        val encryptedResult = cbc.encrypt(message.toByteArray(), ParamsWithIV(key, iv))
        val originalResult = cbc.decrypt(encryptedResult.data, ParamsWithIV(key, iv))

        println(String(originalResult.data))
    }
}