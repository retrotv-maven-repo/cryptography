package dev.retrotv.crypto.util

import dev.retrotv.random.enums.SecurityStrength.MIDDLE
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.RepeatedTest
import java.security.SecureRandom
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RandomGenerateUtilsTest {

    @RepeatedTest(100, name = "{displayName}, {currentRepetition}/{totalRepetitions}")
    @DisplayName("generateBytes() 메소드 테스트")
    fun test_generateBytes_method() {
        var bytes = RandomGenerateUtils.generateBytes()
        assertNotNull(bytes)
        assertEquals(16, bytes.size)

        bytes = RandomGenerateUtils.generateBytes(16)
        assertNotNull(bytes)
        assertEquals(16, bytes.size)

        bytes = RandomGenerateUtils.generateBytes(16, SecureRandom())
        assertNotNull(bytes)
        assertEquals(16, bytes.size)
    }

    @RepeatedTest(100, name = "{displayName}, {currentRepetition}/{totalRepetitions}")
    @DisplayName("generateString() 메소드 테스트")
    fun test_generateString_method() {
        var string = RandomGenerateUtils.generateString()
        assertNotNull(string)
        assertEquals(16, string.length)

        string = RandomGenerateUtils.generateString(16)
        assertNotNull(string)
        assertEquals(16, string.length)
        assertTrue(string.contains(Regex(".*[A-Z]+")))
        assertTrue(string.contains(Regex(".*[a-z]+")))
        assertTrue(string.contains(Regex(".*[0-9]+")))
        assertFalse(string.contains(Regex(".*[^A-Za-z0-9]+")))

        string = RandomGenerateUtils.generateString(16, MIDDLE)
        assertNotNull(string)
        assertEquals(16, string.length)
        assertTrue(string.contains(Regex(".*[A-Z]+")))
        assertTrue(string.contains(Regex(".*[a-z]+")))
        assertTrue(string.contains(Regex(".*[0-9]+")))
        assertFalse(string.contains(Regex(".*[^A-Za-z0-9]+")))

        string = RandomGenerateUtils.generateString(16, MIDDLE, SecureRandom())
        assertNotNull(string)
        assertEquals(16, string.length)
        assertTrue(string.contains(Regex(".*[A-Z]+")))
        assertTrue(string.contains(Regex(".*[a-z]+")))
        assertTrue(string.contains(Regex(".*[0-9]+")))
        assertFalse(string.contains(Regex(".*[^A-Za-z0-9]+")))
    }
}