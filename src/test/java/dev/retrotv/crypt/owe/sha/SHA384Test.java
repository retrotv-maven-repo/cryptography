package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SHA384Test extends OWETest {

    @Test
    @DisplayName("SHA384 File hash 테스트")
    void crc32FileHashTest() throws Exception {
        fileHash(Algorithm.SHA384);
    }
}
