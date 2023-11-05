package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.HashAlgorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SHA1Test : OWETest() {
    @Test
    @DisplayName("SHA1 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(HashAlgorithm.SHA1)
    }

    @Test
    @DisplayName("SHA1 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA1(), HashAlgorithm.SHA1)
    }

    @Test
    @DisplayName("SHA1 File and File matches 테스트")
    @Throws(Exception::class)
    fun fileMatchesTest() {
        fileMatchesTest(SHA1())
    }

    @Test
    @DisplayName("SHA1 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA1())
    }
}
