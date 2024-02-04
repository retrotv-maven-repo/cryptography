package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.AES
import dev.retrotv.crypto.twe.mode.CBC
import kotlin.test.Test

class AESTest {

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