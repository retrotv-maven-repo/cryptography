package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class MD4Test extends OWETest {

    @Test
    @DisplayName("MD4 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(Algorithm.MD4);
    }

    @Test
    @DisplayName("MD4 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new MD4(), Algorithm.MD4);
    }

    @Test
    @DisplayName("MD4 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new MD4());
    }
}
