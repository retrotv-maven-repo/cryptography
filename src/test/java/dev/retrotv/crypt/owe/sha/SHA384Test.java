package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.enums.HashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA384Test extends OWETest {

    @Test
    @DisplayName("SHA384 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(HashAlgorithm.SHA384);
    }

    @Test
    @DisplayName("SHA384 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new SHA384(), HashAlgorithm.SHA384);
    }

    @Test
    @DisplayName("SHA384 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new SHA384());
    }

    @Test
    @DisplayName("SHA384 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SHA384());
    }
}
