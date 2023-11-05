package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.HashAlgorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SHA384Test : OWETest() {
    @Test
    @DisplayName("SHA384 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(HashAlgorithm.SHA384)
    }

    @Test
    @DisplayName("SHA384 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(SHA384(), HashAlgorithm.SHA384)
    }

    @Test
    @DisplayName("SHA384 File and File matches 테스트")
    @Throws(
        Exception::class
    )
    fun fileMatchesTest() {
        fileMatchesTest(SHA384())
    }

    @Test
    @DisplayName("SHA384 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SHA384())
    }
}
