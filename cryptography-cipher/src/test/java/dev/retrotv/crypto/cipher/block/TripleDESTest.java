package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.block.algorithm.TripleDES;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class TripleDESTest {
    private final BlockChiperTest test = new BlockChiperTest();

    @DisplayName("TripleDES 암호화 테스트")
    @ParameterizedTest(name = "TripleDES keyLength: {0}")
    @ValueSource(ints = {16, 24})
    void testTripleDES(int keyLength) {
        test.test_ecb(new TripleDES(), keyLength);
    }

    @DisplayName("TripleDES - CBC 암호화 테스트")
    @ParameterizedTest(name = "TripleDES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,8", "24,8"})
    void testCBC(int keyLength, int ivLength) {
        test.test_cbc(new TripleDES(), keyLength, ivLength);
    }

    @DisplayName("TripleDES - OFB 암호화 테스트")
    @ParameterizedTest(name = "TripleDES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,8", "24,8"})
    void testOFB(int keyLength, int ivLength) {
        test.test_ofb(new TripleDES(), keyLength, ivLength);
    }

    @DisplayName("TripleDES - CFB 암호화 테스트")
    @ParameterizedTest(name = "TripleDES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,8", "24,8"})
    void testCFB(int keyLength, int ivLength) {
        test.test_cfb(new TripleDES(), keyLength, ivLength);
    }
}

