package dev.retrotv.crypto.password.pbkdf2

import org.junit.jupiter.api.DisplayName
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Pbkdf2Test {
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("BCrypt 암호화 테스트")
    fun test_bcrypt() {
        var pbkdf2 = Pbkdf2()
        var encodedPassword = pbkdf2.encode(password)
        assertNotEquals(password, encodedPassword)

        var encodedPassword2 = pbkdf2.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(pbkdf2.matches(password, encodedPassword))
        assertTrue(pbkdf2.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        pbkdf2 = Pbkdf2(
            password,
            16,
            1000,
            PBKDF2WithHmacSHA256
        )
        encodedPassword = pbkdf2.encode(password)
        assertNotEquals(password, encodedPassword)

        encodedPassword2 = pbkdf2.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(pbkdf2.matches(password, encodedPassword))
        assertTrue(pbkdf2.matches(password, encodedPassword2))
    }
}