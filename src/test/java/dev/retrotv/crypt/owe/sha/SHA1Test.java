package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA1Test extends OWETest {

    @Test
    @DisplayName("SHA1 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(Algorithm.SHA1);
    }

    @Test
    @DisplayName("SHA1 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new SHA1(), Algorithm.SHA1);
    }

    @Test
    @DisplayName("SHA1 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new SHA1());
    }

    @Test
    @DisplayName("SHA1 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SHA1());
    }
}
