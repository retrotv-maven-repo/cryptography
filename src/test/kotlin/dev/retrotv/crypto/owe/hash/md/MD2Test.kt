package dev.retrotv.crypto.owe.hash.md

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class MD2Test : OWETest() {
    @Test
    @DisplayName("MD2 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.MD2)
    }

    @Test
    @DisplayName("MD2 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(MD2(), Algorithm.Hash.MD2)
    }

    @Test
    @DisplayName("MD2 File and File matches 테스트")
    @Throws(Exception::class)
    fun fileMatchesTest() {
        fileMatchesTest(MD2())
    }

    @Test
    @DisplayName("MD2 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(MD2())
    }
}
