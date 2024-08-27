package dev.retrotv.crypto.password.pbkdf2

import dev.retrotv.crypto.password.KDFTest
import org.junit.jupiter.api.DisplayName
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Pbkdf2Test {
    private val test = KDFTest()
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("BCrypt 암호화 테스트")
    fun test_bcrypt() {
        var pbkdf2 = Pbkdf2()
        test.test_kdf(pbkdf2)

        /* --------------------------------------------------------------- */

        pbkdf2 = Pbkdf2(
            password,
            16,
            1000,
            PBKDF2WithHmacSHA256
        )
        test.test_kdf(pbkdf2)
    }
}