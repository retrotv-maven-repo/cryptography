package dev.retrotv.crypto.owe.hash.crc

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.HashAlgorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class CRC32Test : OWETest() {
    @Test
    @DisplayName("CRC32 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(HashAlgorithm.CRC32)
    }

    @Test
    @DisplayName("CRC32 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(CRC32(), HashAlgorithm.CRC32)
    }

    @Test
    @DisplayName("CRC32 File and File matches 테스트")
    @Throws(
        Exception::class
    )
    fun fileMatchesTest() {
        fileMatchesTest(CRC32())
    }

    @Test
    @DisplayName("CRC32 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(CRC32())
    }
}
