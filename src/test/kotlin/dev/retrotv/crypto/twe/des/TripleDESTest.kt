package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.TripleDES
import dev.retrotv.crypto.twe.mode.CBC
import kotlin.test.Test

class TripleDESTest {

    @Test
    fun test_default() {
        val message = "The lazy dog jumps over the brown fox!"
        val des = TripleDES()
        val cbc = CBC(des)
        val iv = cbc.generateIV()
        val key = des.generateKey()

        val encryptedResult = cbc.encrypt(message.toByteArray(), ParamsWithIV(key, iv))
        val originalResult = cbc.decrypt(encryptedResult.data, ParamsWithIV(key, iv))

        println(String(originalResult.data))
    }
}