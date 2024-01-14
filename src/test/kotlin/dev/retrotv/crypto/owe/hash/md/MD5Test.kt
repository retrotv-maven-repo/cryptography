package dev.retrotv.crypto.owe.hash.md

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class MD5Test : OWETest() {
    @Test
    @DisplayName("MD5 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.MD5)
    }

    @Test
    @DisplayName("MD5 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(MD5(), Algorithm.Hash.MD5)
    }

    @Test
    @DisplayName("MD5 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(MD5())
    }
}
