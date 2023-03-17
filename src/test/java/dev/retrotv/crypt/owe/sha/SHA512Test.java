package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.crypt.owe.crc.CRC32;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA512Test extends OWETest {

    @Test
    @DisplayName("SHA512 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHash(Algorithm.SHA512);
    }

    @Test
    @DisplayName("SHA512 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchs(new SHA512(), Algorithm.SHA512);
    }

    @Test
    @DisplayName("SHA512 password encode 테스트")
    void passwordEncrypt() {
        passwordEncrypt(new SHA512());
    }
}
