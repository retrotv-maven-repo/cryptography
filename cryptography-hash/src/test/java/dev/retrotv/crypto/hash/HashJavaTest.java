package dev.retrotv.crypto.hash;

import dev.retrotv.crypto.enums.EHash;
import dev.retrotv.crypto.util.CodecUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HashJavaTest {
    private static final String PASSWORD = "The quick brown fox jumps over the lazy dog";

    @Test
    @DisplayName("CRC-32 알고리즘으로 해싱")
    void test_crc32() {
        Set<String> hashedResults = new HashSet<>();
        Hash h = Hash.getInstance(EHash.CRC32);
        for (int i = 0; i < 100; i++) {
            hashedResults.add(CodecUtils.encode(h.hash(PASSWORD)));
        }

        assertEquals(1, hashedResults.size());
    }
}
