package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.encryption.generator.generateKey
import dev.retrotv.crypto.encryption.mode.CBC
import dev.retrotv.crypto.encryption.mode.CFB
import dev.retrotv.crypto.encryption.mode.ECB
import dev.retrotv.crypto.encryption.mode.OFB
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.param.ParamsWithIV
import sun.security.util.Length
import kotlin.test.assertEquals

class BlockChiperTest {

    fun test_ecb(blockCipher: BlockCipher, keyLength: Int) {
        val mode = ECB(blockCipher)

        val plainText = "Hello, World!"
        val key = generateKey(keyLength)
        val params = Params(key)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_cbc(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CBC(blockCipher)

        val plainText = "Hello, World!"
        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamsWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_ofb(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = OFB(blockCipher)

        val plainText = "Hello, World!"
        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamsWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }

    fun test_cfb(blockCipher: BlockCipher, keyLength: Int, ivLength: Int) {
        val mode = CFB(blockCipher)

        val plainText = "Hello, World!"
        val key = generateKey(keyLength)
        val iv = generateKey(ivLength)
        val params = ParamsWithIV(key, iv)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }
}