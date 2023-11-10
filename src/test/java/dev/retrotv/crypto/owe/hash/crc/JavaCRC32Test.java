package dev.retrotv.crypto.owe.hash.crc;

import dev.retrotv.crypto.owe.hash.Checksum;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

class JavaCRC32Test {

    @Test
    @DisplayName("fileMatch")
    void test_fileMatch() throws IOException {
        Checksum checksum = new CRC32();
        // checksum.matches((File) null, (File) null);
    }
}
