package dev.retrotv.crypto.encryption.block

import kotlin.test.Test

class ARIATest {
    private val test = BlockChiperTest()

    @Test
    fun testARIA() {
        test.test_ecb(ARIA())
    }
}