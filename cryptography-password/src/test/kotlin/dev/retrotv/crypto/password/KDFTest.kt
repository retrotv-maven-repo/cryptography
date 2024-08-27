package dev.retrotv.crypto.password

import kotlin.test.*

class KDFTest {
    private val password = "The lazy dog jumps over the quick brown fox"

    fun test_kdf(kdf: KDF) {
        val encodedPassword = kdf.encode(password)
        assertNotEquals(password, encodedPassword)

        val encodedPassword2 = kdf.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertFalse(kdf.matches(null, encodedPassword))
        assertTrue(kdf.matches(password, encodedPassword))
        assertTrue(kdf.matches(password, encodedPassword2))
    }
}