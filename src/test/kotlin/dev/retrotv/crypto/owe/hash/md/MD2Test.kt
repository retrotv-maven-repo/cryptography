package dev.retrotv.crypto.owe.hash.md

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class MD2Test : OWETest() {
    @Test
    @DisplayName("MD2 File hash 테스트")
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.MD2)
    }

    @Test
    @DisplayName("MD2 File hash matches 테스트")
    fun fileHashMatchesTest() {
        fileHashMatchesTest(MD2(), Algorithm.Hash.MD2)
    }

    @Test
    @DisplayName("MD2 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(MD2())
    }
}
