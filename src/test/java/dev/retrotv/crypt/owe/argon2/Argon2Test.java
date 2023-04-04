package dev.retrotv.crypt.owe.argon2;

import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.crypt.owe.Password;
import dev.retrotv.crypt.owe.PasswordWithSalt;
import dev.retrotv.crypt.owe.crc.CRC32;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class Argon2Test extends OWETest {

    @Test
    @DisplayName("Argon2 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new Argon2());
    }
}
