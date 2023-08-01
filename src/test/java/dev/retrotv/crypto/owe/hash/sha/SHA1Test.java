package dev.retrotv.crypto.owe.hash.sha;

import dev.retrotv.crypto.owe.OWETest;
import dev.retrotv.enums.HashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA1Test extends OWETest {

    @Test
    @DisplayName("SHA1 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(HashAlgorithm.SHA1);
    }

    @Test
    @DisplayName("SHA1 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new SHA1(), HashAlgorithm.SHA1);
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
