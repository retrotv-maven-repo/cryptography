package dev.retrotv.crypto.encryption.block

import kotlin.test.Test

class DESTest {
    private val test = BlockChiperTest()

    @Test
    fun testDES() {
        test.test_ecb(DES())
    }
}