package dev.retrotv.crypto.password.bcrypt

import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class BCryptTest {
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("BCrypt 암호화 테스트")
    fun test_bcrypt() {
        val bCrypt = BCrypt()
        val encodedPassword = bCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        val encodedPassword2 = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(bCrypt.matches(password, encodedPassword))
        assertTrue(bCrypt.matches(password, encodedPassword2))
    }
}