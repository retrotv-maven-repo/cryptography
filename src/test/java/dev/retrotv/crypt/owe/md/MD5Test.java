package dev.retrotv.crypt.owe.md;

import dev.retrotv.enums.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class MD5Test extends OWETest {

    @Test
    @DisplayName("MD5 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(Algorithm.MD5);
    }

    @Test
    @DisplayName("MD5 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new MD5(), Algorithm.MD5);
    }

    @Test
    @DisplayName("MD5 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new MD5());
    }

    @Test
    @DisplayName("MD5 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new MD5());
    }
}
