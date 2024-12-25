package dev.retrotv.crypto.hash;

import dev.retrotv.crypto.enums.EHash;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

class HashJavaTest {
    private final static String PASSWORD = "The quick brown fox jumps over the lazy dog";

    @Test
    @DisplayName("CRC-32 알고리즘으로 해싱")
    void test_crc32() {
        Set<String> hashedResults = new HashSet<>();
        Hash h = Hash.getInstance(EHash.CRC32);
        for (int i = 0; i < 100; i++) {
            hashedResults.add(h.hash(PASSWORD));
        }

        assert hashedResults.size() == 1;
    }
}
