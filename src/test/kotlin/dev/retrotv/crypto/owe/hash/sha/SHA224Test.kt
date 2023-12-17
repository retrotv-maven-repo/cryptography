package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SHA224Test : OWETest() {
    @Test
    @DisplayName("SHA224 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.SHA224)
    }

    @Test
    @DisplayName("SHA224 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA224(), Algorithm.Hash.SHA224)
    }

    @Test
    @DisplayName("SHA224 File and File matches 테스트")
    @Throws(
        Exception::class
    )
    fun fileMatchesTest() {
        fileMatchesTest(SHA224())
    }

    @Test
    @DisplayName("SHA224 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA224())
    }
}
