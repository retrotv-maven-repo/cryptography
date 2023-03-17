package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.crypt.owe.crc.CRC32;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA224Test extends OWETest {

    @Test
    @DisplayName("SHA224 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHash(Algorithm.SHA224);
    }

    @Test
    @DisplayName("SHA224 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchs(new SHA224(), Algorithm.SHA224);
    }

    @Test
    @DisplayName("SHA224 password encode 테스트")
    void passwordEncrypt() {
        passwordEncrypt(new SHA224());
    }
}
