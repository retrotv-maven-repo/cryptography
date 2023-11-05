package dev.retrotv.crypto.owe.kdf.argon2

import dev.retrotv.crypto.owe.OWETest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class Argon2Test : OWETest() {
    @Test
    @DisplayName("Argon2 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(Argon2())
    }
}
