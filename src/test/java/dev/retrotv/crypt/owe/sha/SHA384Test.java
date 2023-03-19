package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA384Test extends OWETest {

    @Test
    @DisplayName("SHA384 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHash(Algorithm.SHA384);
    }

    @Test
    @DisplayName("SHA384 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchs(new SHA384(), Algorithm.SHA384);
    }

    @Test
    @DisplayName("SHA384 password encode 테스트")
    void passwordEncrypt() {
        passwordEncrypt(new SHA384());
    }
}
