package dev.retrotv.crypt.owe.hash.md;

import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.crypt.owe.hash.md.MD2;
import dev.retrotv.enums.HashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class MD2Test extends OWETest {

    @Test
    @DisplayName("MD2 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(HashAlgorithm.MD2);
    }

    @Test
    @DisplayName("MD2 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new MD2(), HashAlgorithm.MD2);
    }

    @Test
    @DisplayName("MD2 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new MD2());
    }

    @Test
    @DisplayName("MD2 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new MD2());
    }
}
