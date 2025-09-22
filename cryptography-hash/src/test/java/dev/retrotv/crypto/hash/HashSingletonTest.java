package dev.retrotv.crypto.hash;

import dev.retrotv.crypto.hash.enums.EHash;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

class HashSingletonTest {

    @Test
    @DisplayName("동일 인스턴스 확인")
    void test_singleton() {
        Hash hash = Hash.getInstance(EHash.SHA1);
        for (int i = 0; i <= 100; i++) {
            Hash anotherHash = Hash.getInstance(EHash.SHA1);
            assertSame(hash, anotherHash);
        }
    }

    @Test
    @DisplayName("다른 인스턴스 확인")
    void test_singleton_different() {
        Hash hash1 = Hash.getInstance(EHash.SHA1);
        Hash hash2 = Hash.getInstance(EHash.SHA256);

        assertNotSame(hash1, hash2);
    }

    @Test
    @DisplayName("인스턴스 변경 확인")
    void test_singleton_change() {
        Hash hash1 = Hash.getInstance(EHash.SHA1);
        Hash hash2 = Hash.getInstance(EHash.SHA256);

        assertNotSame(hash1, hash2);

        Hash hash3 = Hash.getInstance(EHash.SHA1);
        assertNotSame(hash1, hash3);
    }
}
