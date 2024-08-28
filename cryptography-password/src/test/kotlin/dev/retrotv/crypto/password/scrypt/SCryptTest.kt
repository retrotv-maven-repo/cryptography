package dev.retrotv.crypto.password.scrypt

import dev.retrotv.crypto.password.KDFTest
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

class SCryptTest {
    private val test = KDFTest()
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("BCrypt 암호화 테스트")
    fun test_bcrypt() {
        var sCrypt = SCrypt()
        test.test_kdf(sCrypt)

        /* --------------------------------------------------------------- */

        sCrypt = SCrypt(
            65536,
            8,
            1,
            32,
            16
        )
        test.test_kdf(sCrypt)
    }
}