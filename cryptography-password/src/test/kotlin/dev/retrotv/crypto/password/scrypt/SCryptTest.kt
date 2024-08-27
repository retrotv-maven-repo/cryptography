package dev.retrotv.crypto.password.scrypt

import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SCryptTest {
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("BCrypt 암호화 테스트")
    fun test_bcrypt() {
        var sCrypt = SCrypt()
        var encodedPassword = sCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        var encodedPassword2 = sCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(sCrypt.matches(password, encodedPassword))
        assertTrue(sCrypt.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        sCrypt = SCrypt(
            65536,
            8,
            1,
            32,
            16
        )
        encodedPassword = sCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        encodedPassword2 = sCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(sCrypt.matches(password, encodedPassword))
        assertTrue(sCrypt.matches(password, encodedPassword2))
    }
}