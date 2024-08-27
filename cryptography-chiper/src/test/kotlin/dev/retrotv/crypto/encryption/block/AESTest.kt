package dev.retrotv.crypto.encryption.block

import kotlin.test.Test

class AESTest {
    private val test = BlockChiperTest()

    @Test
    fun testAES() {
        test.test_ecb(AES())
    }
}