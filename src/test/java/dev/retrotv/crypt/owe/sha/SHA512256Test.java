package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA512256Test extends OWETest {

    @Test
    @DisplayName("SHA512256 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(Algorithm.SHA512256);
    }

    @Test
    @DisplayName("SHA512256 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new SHA512256(), Algorithm.SHA512256);
    }

    @Test
    @DisplayName("SHA512256 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SHA512256());
    }
}
