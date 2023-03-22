package dev.retrotv.crypt.owe.pbkdf2;

import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class Pbkdf2Test extends OWETest {

    @Test
    @DisplayName("Pbkdf2 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new Pbkdf2());
    }
}
