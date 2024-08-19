package dev.retrotv.crypto.owe.kdf.bcrypt

import dev.retrotv.crypto.owe.OWETest
import dev.retrotv.crypto.owe.password.bcrypt.BCrypt
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion
import java.security.SecureRandom

class BCryptTest : OWETest() {

    @Test
    @DisplayName("BCrypt password encode 테스트")
    fun passwordEncrypt() {
        passwordEncryptAndMatchesTest(BCrypt())
        passwordEncryptAndMatchesTest(BCrypt(10))
        passwordEncryptAndMatchesTest(BCrypt(BCryptVersion.`$2A`))
        passwordEncryptAndMatchesTest(BCrypt(BCryptVersion.`$2A`, SecureRandom()))
        passwordEncryptAndMatchesTest(BCrypt(10, SecureRandom()))
        passwordEncryptAndMatchesTest(BCrypt(BCryptVersion.`$2A`, 10))
        passwordEncryptAndMatchesTest(BCrypt(BCryptVersion.`$2A`, 10, SecureRandom()))
    }
}
