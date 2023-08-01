package dev.retrotv.crypto.owe.kdf.bcrypt;

import dev.retrotv.crypto.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class BCryptTest extends OWETest {

    @Test
    @DisplayName("BCrypt password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new BCrypt());
    }
}
