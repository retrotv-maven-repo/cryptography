package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.encryption.mode.ECB
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.generator.generateKey
import kotlin.test.Test
import kotlin.test.assertEquals

class AESTest {

    @Test
    fun testAES() {
        val aes = AES()
        val mode = ECB(aes)

        val plainText = "Hello, World!"
        val key = generateKey(16)
        val params = Params(key)

        val encrypted = mode.encrypt(plainText.toByteArray(), params)
        val decrypted = mode.decrypt(encrypted.data, params)

        assertEquals(plainText, String(decrypted.data))
    }
}