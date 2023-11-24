package dev.retrotv.crypto.owe.hash.crc;

import dev.retrotv.crypto.owe.hash.Checksum;
import dev.retrotv.crypto.owe.hash.Hash;
import dev.retrotv.data.enums.EncodeFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

class JavaCRC32Test {

    @Test
    @DisplayName("fileMatch")
    void test_fileMatch() throws IOException {
        Hash hash = new CRC32();
        // Checksum checksum = new CRC32();
        // checksum.matches((File) null, (File) null);
    }
}
