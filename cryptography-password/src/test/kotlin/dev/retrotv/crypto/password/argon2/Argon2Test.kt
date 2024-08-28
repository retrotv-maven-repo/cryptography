package dev.retrotv.crypto.password.argon2

import dev.retrotv.crypto.password.KDFTest
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Argon2Test {
    private val test = KDFTest()
    private val password = "The lazy dog jumps over the quick brown fox"

    @Test
    @DisplayName("Argon2 암호화 테스트")
    fun test_argon2() {
        var argon2 = Argon2()
        test.test_kdf(argon2)

        /* --------------------------------------------------------------- */

        argon2 = Argon2(16, 16, 2, 1 shl 14, 2)
        test.test_kdf(argon2)
    }
}