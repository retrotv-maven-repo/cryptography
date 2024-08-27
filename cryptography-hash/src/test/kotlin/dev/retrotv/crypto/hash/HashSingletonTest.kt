package dev.retrotv.crypto.hash

import dev.retrotv.crypto.enums.EHash.*

import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

class HashSingletonTest {

    @Test
    @DisplayName("동일 인스턴스 확인")
    fun test_singleton() {
        val hash = Hash.newInstance(SHA1)
        for (i in 0..100) {
            val anotherHash = Hash.newInstance(SHA1)
            assertSame(hash, anotherHash)
        }
    }

    @Test
    @DisplayName("다른 인스턴스 확인")
    fun test_singleton_different() {
        val hash1 = Hash.newInstance(SHA1)
        val hash2 = Hash.newInstance(SHA256)

        assertNotSame(hash1, hash2)
    }

    @Test
    @DisplayName("인스턴스 변경 확인")
    fun test_singleton_change() {
        val hash1 = Hash.newInstance(SHA1)
        val hash2 = Hash.newInstance(SHA256)

        assertNotSame(hash1, hash2)

        val hash3 = Hash.newInstance(SHA1)
        assertNotSame(hash1, hash3)
    }
}