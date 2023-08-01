package dev.retrotv.crypto.owe.kdf.argon2;

import dev.retrotv.crypto.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class Argon2Test extends OWETest {

    @Test
    @DisplayName("Argon2 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new Argon2());
    }
}
