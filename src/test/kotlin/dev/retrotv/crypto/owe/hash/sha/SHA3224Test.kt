package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

class SHA3224Test : OWETest() {
    @Test
    @DisplayName("SHA3224 File hash 테스트")
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.SHA3224)
    }

    @Test
    @DisplayName("SHA3224 File hash matches 테스트")
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA3224(), Algorithm.Hash.SHA3224)
    }

    @Test
    @DisplayName("SHA3224 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA224())
    }
}