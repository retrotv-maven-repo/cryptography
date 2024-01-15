package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

class SHA3256Test : OWETest() {

    @Test
    @DisplayName("SHA3256 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.SHA3256)
    }

    @Test
    @DisplayName("SHA3256 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA3256(), Algorithm.Hash.SHA3256)
    }

    @Test
    @DisplayName("SHA3256 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA3256())
    }
}