package dev.retrotv.crypto.owe.kdf.bcrypt;

import dev.retrotv.crypto.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class BCryptTest extends OWETest {

    @Test
    @DisplayName("BCrypt password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new BCrypt());
    }

    @Test
    @DisplayName("upgradeEncoding 테스트")
    void test_upgradeEncoding_method() {
        BCrypt bCrypt = new BCrypt();
        assertTrue(bCrypt.upgradeEncoding("!Q@W3e4r"));
    }
}
