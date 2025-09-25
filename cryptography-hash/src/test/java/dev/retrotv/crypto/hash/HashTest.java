package dev.retrotv.crypto.hash;

import dev.retrotv.crypto.exception.AlgorithmNotFoundException;
import dev.retrotv.crypto.hash.enums.EHash;
import dev.retrotv.crypto.util.Base64CodecUtils;
import dev.retrotv.crypto.util.HEXCodecUtils;
import dev.retrotv.data.enums.EncodeFormat;
import org.json.JSONObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

class HashTest {
    private final String password = "The quick brown fox jumps over the lazy dog";
    private final URL checksum = this.getClass().getClassLoader().getResource("hash_code");
    private final URL resource = this.getClass().getClassLoader().getResource("hash_code_test_file.txt");

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("CRC-32 알고리즘으로 해싱")
    void test_crc32() {
        hashingTest(EHash.CRC32);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("MD2 알고리즘으로 해싱")
    void test_md2() {
        hashingTest(EHash.MD2);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("MD5 알고리즘으로 해싱")
    void test_md5() {
        hashingTest(EHash.MD5);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-1 알고리즘으로 해싱")
    void test_sha1() {
        hashingTest(EHash.SHA1);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-224 알고리즘으로 해싱")
    void test_sha224() {
        hashingTest(EHash.SHA224);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-256 알고리즘으로 해싱")
    void test_sha256() {
        hashingTest(EHash.SHA256);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-384 알고리즘으로 해싱")
    void test_sha384() {
        hashingTest(EHash.SHA384);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512 알고리즘으로 해싱")
    void test_sha512() {
        hashingTest(EHash.SHA512);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512/224 알고리즘으로 해싱")
    void test_sha512224() {
        hashingTest(EHash.SHA512224);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512/256 알고리즘으로 해싱")
    void test_sha512256() {
        hashingTest(EHash.SHA512256);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-224 알고리즘으로 해싱")
    void test_sha3224() {
        hashingTest(EHash.SHA3224);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-256 알고리즘으로 해싱")
    void test_sha3256() {
        hashingTest(EHash.SHA3256);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-384 알고리즘으로 해싱")
    void test_sha3384() {
        hashingTest(EHash.SHA3384);
    }

    @RepeatedTest(value = 100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-512 알고리즘으로 해싱")
    void test_sha3512() {
        hashingTest(EHash.SHA3512);
    }

    @Test
    @DisplayName("getInstance(String) 테스트")
    void test_getInstance() {
        Hash h1 = Hash.getInstance("MD5");
        Hash h2 = Hash.getInstance(EHash.MD5);

        assertEquals(HEXCodecUtils.encode(h1.hashing(password)), HEXCodecUtils.encode(h2.hashing(password)));
        assertEquals(Base64CodecUtils.encode(h1.hashing(password)), Base64CodecUtils.encode(h2.hashing(password)));
    }

    @Test
    @DisplayName("AlgorithmNotFoundException 테스트")
    void test_algorithmNotFoundException() {
        assertThrows(AlgorithmNotFoundException.class, () ->
            Hash.getInstance("WRONG_ALGORITHM")
        );
    }

    private void hashingTest(EHash algorithm) {
        passwordHashTest(algorithm);
        fileHashTest(algorithm);
    }

    private void passwordHashTest(EHash algorithm) {
        Hash h = Hash.getInstance(algorithm);
        assertTrue(h.matches(password.getBytes(), getHash(algorithm)));
        assertEquals(HEXCodecUtils.encode(h.hashing(password)), getHash(algorithm));
        assertEquals(HEXCodecUtils.encode(h.hashing(password, java.nio.charset.StandardCharsets.UTF_8)), getHash(algorithm));
    }

    private void fileHashTest(EHash algorithm) {
        BinaryHash h = (BinaryHash) Hash.getInstance(algorithm);

        assertTrue(
                h.matches(
                        getResourceFileBytes(resource),
                        HEXCodecUtils.encode(h.hashing(getResourceFileBytes(resource)))
                )
        );

        assertFalse(h.matches(getResourceFileBytes(resource), (byte[]) null));
        assertFalse(h.matches(getResourceFileBytes(resource), (String) null, EncodeFormat.HEX));
    }

    private String getHash(EHash algorithm) {
        try {
            JSONObject jsonObject = new JSONObject(readJson());
            JSONObject file = jsonObject.getJSONObject("hash_code_test_file");
            switch (algorithm) {
                case CRC32: return file.getString(EHash.CRC32.label());
                case MD2: return file.getString(EHash.MD2.label());
                case MD5: return file.getString(EHash.MD5.label());
                case SHA1: return file.getString(EHash.SHA1.label());
                case SHA224: return file.getString(EHash.SHA224.label());
                case SHA256: return file.getString(EHash.SHA256.label());
                case SHA384: return file.getString(EHash.SHA384.label());
                case SHA512: return file.getString(EHash.SHA512.label());
                case SHA512224: return file.getString(EHash.SHA512224.label());
                case SHA512256: return file.getString(EHash.SHA512256.label());
                case SHA3224: return file.getString(EHash.SHA3224.label());
                case SHA3256: return file.getString(EHash.SHA3256.label());
                case SHA3384: return file.getString(EHash.SHA3384.label());
                case SHA3512: return file.getString(EHash.SHA3512.label());
                default: return null;
            }
        } catch (IOException e) {
            return null;
        }
    }

    private String readJson() throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(checksum.getFile()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    private byte[] getResourceFileBytes(URL resourceUrl) {
        if (resourceUrl == null) return new byte[0];
        try (BufferedReader reader = new BufferedReader(new FileReader(resourceUrl.getFile()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString().getBytes();
        } catch (IOException e) {
            return new byte[0];
        }
    }
}
