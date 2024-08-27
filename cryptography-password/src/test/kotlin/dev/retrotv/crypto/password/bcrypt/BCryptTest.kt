package dev.retrotv.crypto.password.bcrypt

import org.junit.jupiter.api.DisplayName
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class BCryptTest {
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("BCrypt 암호화 테스트")
    fun test_bcrypt() {
        var bCrypt = BCrypt()
        var encodedPassword = bCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        var encodedPassword2 = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(bCrypt.matches(password, encodedPassword))
        assertTrue(bCrypt.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(10)
        encodedPassword = bCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        encodedPassword2 = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(bCrypt.matches(password, encodedPassword))
        assertTrue(bCrypt.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(BCryptVersion.`$2A`)
        encodedPassword = bCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        encodedPassword2 = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(bCrypt.matches(password, encodedPassword))
        assertTrue(bCrypt.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(BCryptVersion.`$2A`, 10)
        encodedPassword = bCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        encodedPassword2 = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(bCrypt.matches(password, encodedPassword))
        assertTrue(bCrypt.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(BCryptVersion.`$2A`, 10, SecureRandom())
        encodedPassword = bCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        encodedPassword2 = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(bCrypt.matches(password, encodedPassword))
        assertTrue(bCrypt.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(10, SecureRandom())
        encodedPassword = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        encodedPassword2 = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(bCrypt.matches(password, encodedPassword))
        assertTrue(bCrypt.matches(password, encodedPassword2))

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(BCryptVersion.`$2A`, SecureRandom())
        encodedPassword = bCrypt.encode(password)
        assertNotEquals(password, encodedPassword)

        encodedPassword2 = bCrypt.encode(password)
        assertNotEquals(encodedPassword, encodedPassword2)

        assertTrue(bCrypt.matches(password, encodedPassword))
        assertTrue(bCrypt.matches(password, encodedPassword2))
    }
}