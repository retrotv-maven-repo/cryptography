package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA512224Test extends OWETest {

    @Test
    @DisplayName("SHA512224 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(Algorithm.SHA512224);
    }

    @Test
    @DisplayName("SHA512224 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new SHA512224(), Algorithm.SHA512224);
    }

    @Test
    @DisplayName("SHA512224 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new SHA512224());
    }

    @Test
    @DisplayName("SHA512224 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SHA512224());
    }
}
