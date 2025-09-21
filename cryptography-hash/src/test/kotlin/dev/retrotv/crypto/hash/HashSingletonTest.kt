package dev.retrotv.crypto.hash

import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

import dev.retrotv.crypto.hash.enums.EHash.*

class HashSingletonTest {

    @Test
    @DisplayName("동일 인스턴스 확인")
    fun test_singleton() {
        val hash = Hash.getInstance(SHA1)
        (0..100).forEach { i ->
            val anotherHash = Hash.getInstance(SHA1)
            assertSame(hash, anotherHash)
        }
    }

    @Test
    @DisplayName("다른 인스턴스 확인")
    fun test_singleton_different() {
        val hash1 = Hash.getInstance(SHA1)
        val hash2 = Hash.getInstance(SHA256)

        assertNotSame(hash1, hash2)
    }

    @Test
    @DisplayName("인스턴스 변경 확인")
    fun test_singleton_change() {
        val hash1 = Hash.getInstance(SHA1)
        val hash2 = Hash.getInstance(SHA256)

        assertNotSame(hash1, hash2)

        val hash3 = Hash.getInstance(SHA1)
        assertNotSame(hash1, hash3)
    }
}