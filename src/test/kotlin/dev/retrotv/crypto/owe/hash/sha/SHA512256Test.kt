package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.HashAlgorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SHA512256Test : OWETest() {
    @Test
    @DisplayName("SHA512256 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(HashAlgorithm.SHA512256)
    }

    @Test
    @DisplayName("SHA512256 File hash matches 테스트")
    @Throws(
        Exception::class
    )
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA512256(), HashAlgorithm.SHA512256)
    }

    @Test
    @DisplayName("SHA512256 File and File matches 테스트")
    @Throws(
        Exception::class
    )
    fun fileMatchesTest() {
        fileMatchesTest(SHA512256())
    }

    @Test
    @DisplayName("SHA512256 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA512256())
    }
}