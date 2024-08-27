package dev.retrotv.crypto.password.argon2

import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Argon2Test {
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("Argon2 암호화 테스트")
    fun test_argon2() {
        var argon2 = Argon2()
        var encodedPassword = argon2.encode(password)
        assertNotEquals(password, encodedPassword)

        var encodedPassword2 = argon2.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(argon2.matches(password, encodedPassword))
        assertTrue(argon2.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        argon2 = Argon2(16, 16, 2, 1 shl 14, 2)
        encodedPassword = argon2.encode(password)
        assertNotEquals(password, encodedPassword)

        encodedPassword2 = argon2.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(argon2.matches(password, encodedPassword))
        assertTrue(argon2.matches(password, encodedPassword2))
    }
}