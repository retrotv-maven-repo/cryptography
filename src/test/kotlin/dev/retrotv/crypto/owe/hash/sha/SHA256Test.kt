package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.HashAlgorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SHA256Test : OWETest() {
    @Test
    @DisplayName("SHA256 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(HashAlgorithm.SHA256)
    }

    @Test
    @DisplayName("SHA256 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA256(), HashAlgorithm.SHA256)
    }

    @Test
    @DisplayName("SHA256 File and File matches 테스트")
    @Throws(
        Exception::class
    )
    fun fileMatchesTest() {
        fileMatchesTest(SHA256())
    }

    @Test
    @DisplayName("SHA256 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA256())
    }
}
