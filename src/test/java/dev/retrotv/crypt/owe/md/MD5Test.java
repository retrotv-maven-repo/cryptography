package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class MD5Test extends OWETest {

    @Test
    @DisplayName("MD5 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHash(Algorithm.MD5);
    }

    @Test
    @DisplayName("MD5 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchs(new MD5(), Algorithm.MD5);
    }

    @Test
    @DisplayName("MD5 password encode 테스트")
    void passwordEncrypt() {
        passwordEncrypt(new MD5());
    }
}
