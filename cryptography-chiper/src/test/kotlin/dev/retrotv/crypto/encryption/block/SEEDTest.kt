package dev.retrotv.crypto.encryption.block

import kotlin.test.Test

class SEEDTest {
    private val test = BlockChiperTest()

    @Test
    fun testSEED() {
        test.test_ecb(SEED())
    }
}