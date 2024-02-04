package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.LEA
import dev.retrotv.crypto.twe.mode.CBC
import kotlin.test.Test

class LEATest {

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