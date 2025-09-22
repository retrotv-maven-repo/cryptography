package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.block.algorithm.LEA;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class LEATest {
    private final BlockChiperTest test = new BlockChiperTest();

    @DisplayName("LEA 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}")
    @ValueSource(ints = {16, 24, 32})
    void testLEA(int keyLength) {
        test.test_ecb(new LEA(), keyLength);
    }

    @DisplayName("LEA - CBC 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCBC(int keyLength, int ivLength) {
        test.test_cbc(new LEA(), keyLength, ivLength);
    }

    @DisplayName("LEA - OFB 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testOFB(int keyLength, int ivLength) {
        test.test_ofb(new LEA(), keyLength, ivLength);
    }

    @DisplayName("LEA - CFB 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCFB(int keyLength, int ivLength) {
        test.test_cfb(new LEA(), keyLength, ivLength);
    }

    @DisplayName("LEA - CTR 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCTR(int keyLength, int ivLength) {
        test.test_ctr(new LEA(), keyLength, ivLength);
    }

    @DisplayName("LEA - CTSECB 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}")
    @ValueSource(ints = {16, 24, 32})
    void testCTSECB(int keyLength) {
        test.test_ctsecb(new LEA(), keyLength);
    }

    @DisplayName("LEA - CTSCBC 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCTSCBC(int keyLength, int ivLength) {
        test.test_ctscbc(new LEA(), keyLength, ivLength);
    }

    @DisplayName("LEA - CCM 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,12", "24,12", "32,12"})
    void testCCM(int keyLength, int ivLength) {
        test.test_ccm(new LEA(), keyLength, ivLength);
    }

    @DisplayName("LEA - GCM 암호화 테스트")
    @ParameterizedTest(name = "LEA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testGCM(int keyLength, int ivLength) {
        test.test_gcm(new LEA(), keyLength, ivLength);
    }
}

