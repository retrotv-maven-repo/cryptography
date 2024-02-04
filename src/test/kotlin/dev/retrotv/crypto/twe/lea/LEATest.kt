package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.aria.ARIA
import dev.retrotv.crypto.twe.mode.CBC
import kotlin.test.Test

class LEATest {

    @Test
    fun test_default() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEA(128)
        val cbc = CBC(lea.engine)
        val spec = cbc.generateSpec()
        val key = lea.generateKey()

        val encryptedResult = cbc.encrypt(message.toByteArray(), ParamsWithIV(key, spec.iv))
        val originalResult = cbc.decrypt(encryptedResult.data, ParamsWithIV(key, spec.iv))

        println(String(originalResult.data))
    }
}