package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.enums.HashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA256Test extends OWETest {

    @Test
    @DisplayName("SHA256 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(HashAlgorithm.SHA256);
    }

    @Test
    @DisplayName("SHA256 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new SHA256(), HashAlgorithm.SHA256);
    }

    @Test
    @DisplayName("SHA256 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new SHA256());
    }

    @Test
    @DisplayName("SHA256 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SHA256());
    }
}
