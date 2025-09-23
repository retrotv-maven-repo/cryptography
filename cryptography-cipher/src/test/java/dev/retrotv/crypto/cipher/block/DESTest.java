package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.block.algorithm.DES;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S1874")
class DESTest {
    private final BlockChiperTest test = new BlockChiperTest();

    @DisplayName("DES - ECB 암호화 테스트")
    @ParameterizedTest(name = "DES keyLength: {0}")
    @ValueSource(ints = {8})
    void testECB(int keyLength) {
        test.test_ecb(new DES(), keyLength);
    }

    @DisplayName("DES - CBC 암호화 테스트")
    @ParameterizedTest(name = "DES keyLength: {0}, ivLength: {1}")
    @CsvSource({"8,8"})
    void testCBC(int keyLength, int ivLength) {
        test.test_cbc(new DES(), keyLength, ivLength);
    }

    @DisplayName("DES - OFB 암호화 테스트")
    @ParameterizedTest(name = "DES keyLength: {0}, ivLength: {1}")
    @CsvSource({"8,8"})
    void testOFB(int keyLength, int ivLength) {
        test.test_ofb(new DES(), keyLength, ivLength);
    }

    @DisplayName("DES - CFB 암호화 테스트")
    @ParameterizedTest(name = "DES keyLength: {0}, ivLength: {1}")
    @CsvSource({"8,8"})
    void testCFB(int keyLength, int ivLength) {
        test.test_cfb(new DES(), keyLength, ivLength);
    }

    @DisplayName("DES - CTR 암호화 테스트")
    @ParameterizedTest(name = "DES keyLength: {0}, ivLength: {1}")
    @CsvSource({"8,8"})
    void testCTR(int keyLength, int ivLength) {
        test.test_ctr(new DES(), keyLength, ivLength);
    }

    @DisplayName("DES - CTSECB 암호화 테스트")
    @ParameterizedTest(name = "DES keyLength: {0}")
    @ValueSource(ints = {8})
    void testCTSECB(int keyLength) {
        test.test_ctsecb(new DES(), keyLength);
    }

    @DisplayName("DES - CTSCBC 암호화 테스트")
    @ParameterizedTest(name = "DES keyLength: {0}, ivLength: {1}")
    @CsvSource({"8,8"})
    void testCTSCBC(int keyLength, int ivLength) {
        test.test_ctscbc(new DES(), keyLength, ivLength);
    }
}

