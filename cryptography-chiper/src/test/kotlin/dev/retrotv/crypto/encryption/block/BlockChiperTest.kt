package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.encryption.generator.generateKey
import dev.retrotv.crypto.encryption.mode.ECB
import dev.retrotv.crypto.encryption.param.Params
import kotlin.test.assertEquals

class BlockChiperTest {

    fun test_ecb(blockCipher: BlockCipher) {
        val mode = ECB(blockCipher)

        val plainText = "Hello, World!"
        var key = generateKey(16)
        var params = Params(key)

        var encrypted = mode.encrypt(plainText.toByteArray(), params)
        var decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))

        key = generateKey(24)
        params = Params(key)

        encrypted = mode.encrypt(plainText.toByteArray(), params)
        decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))

        if (blockCipher !is TripleDES) {
            key = generateKey(32)
            params = Params(key)

            encrypted = mode.encrypt(plainText.toByteArray(), params)
            decrypted = mode.decrypt(encrypted.data, params)

            assertEquals(plainText, String(decrypted.data))
        }
    }
}