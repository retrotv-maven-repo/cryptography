package dev.retrotv.crypto.encryption.block

import kotlin.test.Test

class LEATest {
    private val test = BlockChiperTest()

    @Test
    fun testLEA() {
        test.test_ecb(LEA())
    }
}