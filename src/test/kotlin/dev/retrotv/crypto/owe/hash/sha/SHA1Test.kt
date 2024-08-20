package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SHA1Test : OWETest() {
    @Test
    @DisplayName("SHA1 File hash 테스트")
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.SHA1)
    }

    @Test
    @DisplayName("SHA1 File hash matches 테스트")
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA1(), Algorithm.Hash.SHA1)
    }

    @Test
    @DisplayName("SHA1 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA1())
    }
}
