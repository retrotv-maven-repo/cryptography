package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA256Test extends OWETest {

    @Test
    @DisplayName("SHA256 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHash(Algorithm.SHA256);
    }

    @Test
    @DisplayName("SHA256 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchs(new SHA256(), Algorithm.SHA256);
    }
}
