package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.twe.AEADResult
import dev.retrotv.crypto.twe.CipherAlgorithm
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.LEA
import dev.retrotv.crypto.twe.mode.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.Test
import kotlin.test.asserter

class LEATest {
    private val message = "The lazy dog jumps over the brown fox!".toByteArray()
    private lateinit var lea: CipherAlgorithm

    @DisplayName("ECB 모드 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ecb(keyLen: Int) {
        this.lea = LEA(keyLen)
        val key = lea.generateKey()
        val mode = ECB(lea)
        val encryptedData = mode.encrypt(message, Params(key))
        val originalData = mode.decrypt(encryptedData.data, Params(key))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CBC 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cbc(keyLen: Int) {
        this.lea = LEA(keyLen)
        val key = lea.generateKey()
        val mode = CBC(lea)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CFB 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cfb(keyLen: Int) {
        this.lea = LEA(keyLen)
        val key = lea.generateKey()
        val mode = CFB(lea)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("OFB 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ofb(keyLen: Int) {
        this.lea = LEA(keyLen)
        val key = lea.generateKey()
        val mode = OFB(lea)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CTR 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ctr(keyLen: Int) {
        this.lea = LEA(keyLen)
        val key = lea.generateKey()
        val mode = CTR(lea)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CTS 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cts(keyLen: Int) {

    }

    @DisplayName("CCM 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ccm(keyLen: Int) {
        this.lea = LEA(keyLen)
        val key = lea.generateKey()
        val mode = CCM(lea)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("GCM 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_gcm(keyLen: Int) {
        this.lea = LEA(keyLen)
        val key = lea.generateKey()
        val mode = GCM(lea)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv)) as AEADResult
        val originalData = mode.decrypt(encryptedData.data + encryptedData.tag, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    fun test_default() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEA(128)
        val cbc = CBC(lea)
        val iv = cbc.generateIV()
        val key = lea.generateKey()

        val encryptedResult = cbc.encrypt(message.toByteArray(), ParamsWithIV(key, iv))
        val originalResult = cbc.decrypt(encryptedResult.data, ParamsWithIV(key, iv))

        println(String(originalResult.data))
    }
}