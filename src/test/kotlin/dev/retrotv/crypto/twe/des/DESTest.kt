package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.twe.CipherAlgorithm
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.DES
import dev.retrotv.crypto.twe.mode.*
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.asserter

class DESTest {
    private val message = "The lazy dog jumps over the brown fox!".toByteArray()
    private val des: CipherAlgorithm = DES()

    @Test
    @DisplayName("ECB 모드 암호화 테스트")
    fun test_ecb() {
        val key = des.generateKey()
        val mode = ECB(des)
        val encryptedData = mode.encrypt(message, Params(key))
        val originalData = mode.decrypt(encryptedData.data, Params(key))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CBC 모드 암호화 테스트")
    fun test_cbc() {
        val key = des.generateKey()
        val mode = CBC(des)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CFB 모드 암호화 테스트")
    fun test_cfb() {
        val key = des.generateKey()
        val mode = CFB(des)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("OFB 모드 암호화 테스트")
    fun test_ofb() {
        val key = des.generateKey()
        val mode = OFB(des)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CTR 모드 암호화 테스트")
    fun test_ctr() {
        val key = des.generateKey()
        val mode = CTR(des)
        val iv = mode.generateIV()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CTS 모드 암호화 테스트")
    fun test_cts() {

    }

    @Test
    fun test_default() {
        val message = "The lazy dog jumps over the brown fox!"
        val des = DES()
        val cbc = CBC(des)
        val iv = cbc.generateIV()
        val key = des.generateKey()

        val encryptedResult = cbc.encrypt(message.toByteArray(), ParamsWithIV(key, iv))
        val originalResult = cbc.decrypt(encryptedResult.data, ParamsWithIV(key, iv))

        println(String(originalResult.data))
    }
}