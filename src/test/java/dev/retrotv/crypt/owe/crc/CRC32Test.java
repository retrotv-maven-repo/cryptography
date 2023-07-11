package dev.retrotv.crypt.owe.crc;

import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.enums.HashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class CRC32Test extends OWETest {

    @Test
    @DisplayName("CRC32 File hash 테스트")
    void fileHashTest() throws Exception {
        fileHashTest(HashAlgorithm.CRC32);
    }

    @Test
    @DisplayName("CRC32 File hash matches 테스트")
    void fileHashMatchesTest() throws Exception {
        fileHashMatchesTest(new CRC32(), HashAlgorithm.CRC32);
    }

    @Test
    @DisplayName("CRC32 File and File matches 테스트")
    void fileMatchesTest() throws Exception {
        fileMatchesTest(new CRC32());
    }

    @Test
    @DisplayName("CRC32 password encode 테스트")
    void passwordEncrypt() {
        passwordEncryptAndMatchesTest(new CRC32());
    }
}
