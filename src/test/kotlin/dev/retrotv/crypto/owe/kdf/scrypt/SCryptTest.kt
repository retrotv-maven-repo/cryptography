package dev.retrotv.crypto.owe.kdf.scrypt

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.crypto.owe.password.scrypt.SCrypt
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class SCryptTest : OWETest() {
    @Test
    @DisplayName("SCrypt password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(SCrypt())
    }
}
