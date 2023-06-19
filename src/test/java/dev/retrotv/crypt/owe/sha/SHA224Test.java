package dev.retrotv.crypt.owe.sha;

import dev.retrotv.enums.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA224Test extends OWETest {

    @Test
    @DisplayName("SHA224 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(Algorithm.SHA224);
    }

    @Test
    @DisplayName("SHA224 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new SHA224(), Algorithm.SHA224);
    }

    @Test
    @DisplayName("SHA224 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new SHA224());
    }

    @Test
    @DisplayName("SHA224 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SHA224());
    }
}
