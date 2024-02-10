package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.twe.BlockCipherAlgorithm
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.DES
import dev.retrotv.crypto.twe.mode.*
import dev.retrotv.utils.generate
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.asserter

class DESTest {
    private val message = "The lazy dog jumps over the brown fox!".toByteArray()
    private val des = DES()

    @Test
    @DisplayName("ECB 모드 암호화 테스트")
    fun test_ecb() {
        val key = des.generateKey()
        val mode = ECB()
        val encryptedData = mode.encrypt(message, Params(key))
        val originalData = mode.decrypt(encryptedData.data, Params(key))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CBC 모드 암호화 테스트")
    fun test_cbc() {
        val key = des.generateKey()
        val mode = CBC()
        val iv = generate(8)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CFB 모드 암호화 테스트")
    fun test_cfb() {
        val key = des.generateKey()
        val mode = CFB()
        val iv = generate(8)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("OFB 모드 암호화 테스트")
    fun test_ofb() {
        val key = des.generateKey()
        val mode = OFB()
        val iv = generate(8)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CTR 모드 암호화 테스트")
    fun test_ctr() {
        val key = des.generateKey()
        val mode = CTR()
        val iv = generate(8)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CTS 모드 암호화 테스트")
    fun test_cts() {

    }
}