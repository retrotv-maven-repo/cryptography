package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA512224Test extends OWETest {

    @Test
    @DisplayName("SHA512224 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHash(Algorithm.SHA512224);
    }

    @Test
    @DisplayName("SHA512224 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchs(new SHA512224(), Algorithm.SHA512224);
    }
}
