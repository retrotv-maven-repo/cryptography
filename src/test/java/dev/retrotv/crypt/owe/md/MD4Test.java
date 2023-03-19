package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class MD4Test extends OWETest {

    @Test
    @DisplayName("MD5 password encode 테스트")
    void passwordEncrypt() {
        passwordEncrypt(new MD4());
    }
}
