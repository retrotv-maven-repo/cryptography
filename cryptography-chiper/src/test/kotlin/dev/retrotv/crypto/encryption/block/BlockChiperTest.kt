package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.encryption.generator.generateKey
import dev.retrotv.crypto.encryption.mode.*
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.param.ParamsWithIV
import org.bouncycastle.crypto.params.KeyParameter
import sun.security.util.Length
import kotlin.test.assertEquals

class BlockChiperTest {
    private val plainText = "The quick brown fox jumps over the lazy dog"

    fun test_ecb(blockCipher: BlockCipher, keyLength: Int) {
        val mode = ECB(blockCipher)
        val key = generateKey(keyLength)
        val params = Params(key)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_cbc(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CBC(blockCipher)
        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamsWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ofb(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = OFB(blockCipher)
        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamsWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_cfb(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CFB(blockCipher)
        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamsWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ctr(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CTR(blockCipher)
        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamsWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ctsecb(blockCipher: BlockCipher, keyLength: Int) {
        val mode = CTS(blockCipher)

        val key = generateKey(keyLength)
        val params = Params(key)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ctscbc(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CTS(blockCipher)
        mode.useCBCMode()

        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamsWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }
}