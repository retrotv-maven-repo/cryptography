package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.DES
import dev.retrotv.crypto.twe.mode.CBC
import kotlin.test.Test

class DESTest {

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