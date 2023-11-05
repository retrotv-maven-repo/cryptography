package dev.retrotv.crypto.owe.hash.md

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.HashAlgorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class MD5Test : OWETest() {
    @Test
    @DisplayName("MD5 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(HashAlgorithm.MD5)
    }

    @Test
    @DisplayName("MD5 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(MD5(), HashAlgorithm.MD5)
    }

    @Test
    @DisplayName("MD5 File and File matches 테스트")
    @Throws(Exception::class)
    fun fileMatchesTest() {
        fileMatchesTest(MD5())
    }

    @Test
    @DisplayName("MD5 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(MD5())
    }
}
