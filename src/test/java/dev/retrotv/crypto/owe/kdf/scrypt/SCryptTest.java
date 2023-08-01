package dev.retrotv.crypto.owe.kdf.scrypt;

import dev.retrotv.crypto.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SCryptTest extends OWETest {

    @Test
    @DisplayName("SCrypt password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SCrypt());
    }
}
