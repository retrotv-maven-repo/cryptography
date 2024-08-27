package dev.retrotv.crypto.password.bcrypt

import dev.retrotv.crypto.password.KDFTest
import org.junit.jupiter.api.DisplayName
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class BCryptTest {
    private val test = KDFTest()
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("BCrypt 암호화 테스트")
    fun test_bcrypt() {
        var bCrypt = BCrypt()
        test.test_kdf(bCrypt)

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(10)
        test.test_kdf(bCrypt)

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(BCryptVersion.`$2A`)
        test.test_kdf(bCrypt)

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(BCryptVersion.`$2A`, 10)
        test.test_kdf(bCrypt)

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(BCryptVersion.`$2A`, 10, SecureRandom())
        test.test_kdf(bCrypt)

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(10, SecureRandom())
        test.test_kdf(bCrypt)

        /* --------------------------------------------------------------- */

        bCrypt = BCrypt(BCryptVersion.`$2A`, SecureRandom())
        test.test_kdf(bCrypt)
    }
}