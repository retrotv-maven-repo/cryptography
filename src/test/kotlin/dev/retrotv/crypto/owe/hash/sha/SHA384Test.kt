package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SHA384Test : OWETest() {
    @Test
    @DisplayName("SHA384 File hash 테스트")
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.SHA384)
    }

    @Test
    @DisplayName("SHA384 File hash matches 테스트")
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA384(), Algorithm.Hash.SHA384)
    }

    @Test
    @DisplayName("SHA384 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA384())
    }
}
