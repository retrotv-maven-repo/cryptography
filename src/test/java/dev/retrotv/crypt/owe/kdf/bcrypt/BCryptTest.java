package dev.retrotv.crypt.owe.kdf.bcrypt;

import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class BCryptTest extends OWETest {

    @Test
    @DisplayName("BCrypt password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new BCrypt());
    }
}
