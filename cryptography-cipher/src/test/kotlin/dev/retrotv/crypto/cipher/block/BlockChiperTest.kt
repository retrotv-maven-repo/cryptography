package dev.retrotv.crypto.cipher.block

import dev.retrotv.crypto.cipher.block.mode.CBC
import dev.retrotv.crypto.cipher.block.mode.CCM
import dev.retrotv.crypto.cipher.block.mode.CFB
import dev.retrotv.crypto.cipher.block.mode.CTR
import dev.retrotv.crypto.cipher.block.mode.CTS
import dev.retrotv.crypto.cipher.block.mode.ECB
import dev.retrotv.crypto.cipher.block.mode.GCM
import dev.retrotv.crypto.cipher.block.mode.OFB
import dev.retrotv.crypto.cipher.generator.IVGenerator.generateIV
import dev.retrotv.crypto.cipher.generator.KeyGenerator.generateKey
import dev.retrotv.crypto.cipher.param.Param
import dev.retrotv.crypto.cipher.param.ParamWithIV
import kotlin.test.assertEquals

class BlockChiperTest {
    private val plainText = "The quick brown fox jumps over the lazy dog"

    fun test_ecb(blockCipher: BlockCipher, keyLength: Int) {
        val mode = ECB(blockCipher)
        val key = generateKey(keyLength)
        val params = Param(key)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_cbc(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CBC(blockCipher)
        val key = generateKey(keyLength)
        val iv = generateIV(ivLength)
        val params = ParamWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ofb(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = OFB(blockCipher)
        val key = generateKey(keyLength)
        val iv = generateIV(ivLength)
        val params = ParamWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_cfb(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CFB(blockCipher)
        val key = generateKey(keyLength)
        val iv = generateIV(ivLength)
        val params = ParamWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ctr(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CTR(blockCipher)
        val key = generateKey(keyLength)
        val iv = generateIV(ivLength)
        val params = ParamWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ctsecb(blockCipher: BlockCipher, keyLength: Int) {
        val mode = CTS(blockCipher)

        val key = generateKey(keyLength)
        val params = Param(key)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ctscbc(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CTS(blockCipher)
        mode.useCBCMode()

        val key = generateKey(keyLength)
        val iv = generateIV(ivLength)
        val params = ParamWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ccm(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CCM(blockCipher)

        val key = generateKey(keyLength)
        val iv = generateIV(ivLength)
        val params = ParamWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_gcm(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = GCM(blockCipher)

        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }
}