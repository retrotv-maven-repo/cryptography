package dev.retrotv.crypto.owe.kdf.pbkdf2

import dev.retrotv.crypto.owe.OWETest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class Pbkdf2Test : OWETest() {
    @Test
    @DisplayName("Pbkdf2 password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(Pbkdf2())
    }
}
