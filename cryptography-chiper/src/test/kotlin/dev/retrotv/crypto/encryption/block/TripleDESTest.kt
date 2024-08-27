package dev.retrotv.crypto.encryption.block

import kotlin.test.Test

class TripleDESTest {
    private val test = BlockChiperTest()

    @Test
    fun testTripleDES() {
        test.test_ecb(TripleDES())
    }
}