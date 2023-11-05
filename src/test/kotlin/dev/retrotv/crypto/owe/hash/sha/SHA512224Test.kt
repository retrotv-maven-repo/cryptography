package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.HashAlgorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SHA512224Test : OWETest() {
    @Test
    @DisplayName("SHA512224 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(HashAlgorithm.SHA512224)
    }

    @Test
    @DisplayName("SHA512224 File hash matches 테스트")
    @Throws(
        Exception::class
    )
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA512224(), HashAlgorithm.SHA512224)
    }

    @Test
    @DisplayName("SHA512224 File and File matches 테스트")
    @Throws(
        Exception::class
    )
    fun fileMatchesTest() {
        fileMatchesTest(SHA512224())
    }

    @Test
    @DisplayName("SHA512224 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA512224())
    }
}
