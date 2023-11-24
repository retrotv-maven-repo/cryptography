package dev.retrotv.crypto.owe.kdf.bcrypt

import dev.retrotv.crypto.owe.OWETest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class BCryptTest : OWETest() {
    @Test
    @DisplayName("BCrypt password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(BCrypt())
    }
}
