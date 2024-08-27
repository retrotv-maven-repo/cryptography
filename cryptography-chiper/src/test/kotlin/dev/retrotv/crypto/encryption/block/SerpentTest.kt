package dev.retrotv.crypto.encryption.block

import kotlin.test.Test

class SerpentTest {
    private val test = BlockChiperTest()

    @Test
    fun testSerpent() {
        test.test_ecb(Serpent())
    }
}