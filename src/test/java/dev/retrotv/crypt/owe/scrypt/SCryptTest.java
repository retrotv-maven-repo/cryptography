package dev.retrotv.crypt.owe.scrypt;

import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.crypt.owe.argon2.Argon2;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SCryptTest extends OWETest {

    @Test
    @DisplayName("SCrypt password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SCrypt());
    }
}
