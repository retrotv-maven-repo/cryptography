package dev.retrotv.crypto.owe.hash.crc

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.enums.Algorithm
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

internal class CRC32Test : OWETest() {
    @Test
    @DisplayName("CRC32 File hash 테스트")
    @Throws(Exception::class)
    fun fileHashTest() {
        fileHashTest(Algorithm.Hash.CRC32)
    }

    @Test
    @DisplayName("CRC32 File hash matches 테스트")
    @Throws(Exception::class)
    fun fileHashMatchesTest() {
        fileHashMatchesTest(CRC32(), Algorithm.Hash.CRC32)
    }

    @Test
    @DisplayName("CRC32 File and File matches 테스트")
    @Throws(Exception::class)
    fun fileMatchesTest() {
        fileMatchesTest(CRC32())
    }

    @Test
    @DisplayName("CRC32 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(CRC32())
    }
}
