package dev.retrotv.crypto.owe.hash.sha;

import dev.retrotv.crypto.owe.OWETest;
import dev.retrotv.enums.HashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA512256Test extends OWETest {

    @Test
    @DisplayName("SHA512256 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(HashAlgorithm.SHA512256);
    }

    @Test
    @DisplayName("SHA512256 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new SHA512256(), HashAlgorithm.SHA512256);
    }

    @Test
    @DisplayName("SHA512256 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new SHA512256());
    }

    @Test
    @DisplayName("SHA512256 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new SHA512256());
    }
}
