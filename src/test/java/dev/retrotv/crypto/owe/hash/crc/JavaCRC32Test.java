package dev.retrotv.crypto.owe.hash.crc;

import dev.retrotv.crypto.owe.hash.HashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class JavaCRC32Test {

    @Test
    @DisplayName("fileMatch")
    void test_fileMatch() throws IOException {
        HashAlgorithm hash = new CRC32();
    }
}
