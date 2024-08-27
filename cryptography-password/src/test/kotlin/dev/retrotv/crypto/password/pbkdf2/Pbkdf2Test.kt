package dev.retrotv.crypto.password.pbkdf2

import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Pbkdf2Test {
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("BCrypt 암호화 테스트")
    fun test_bcrypt() {
        val pbkdf2 = Pbkdf2()
        val encodedPassword = pbkdf2.encode(password)
        assertNotEquals(password, encodedPassword)

        val encodedPassword2 = pbkdf2.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(pbkdf2.matches(password, encodedPassword))
        assertTrue(pbkdf2.matches(password, encodedPassword2))
    }
}