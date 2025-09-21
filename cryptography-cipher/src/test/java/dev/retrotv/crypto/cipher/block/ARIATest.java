package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.block.algorithm.ARIA;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class ARIATest {
    private final BlockChiperTest test = new BlockChiperTest();

    @DisplayName("ARIA - ECB 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}")
    @ValueSource(ints = {16, 24, 32})
    void testECB(int keyLength) {
        test.test_ecb(new ARIA(), keyLength);
    }

    @DisplayName("ARIA - CBC 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCBC(int keyLength, int ivLength) {
        test.test_cbc(new ARIA(), keyLength, ivLength);
    }

    @DisplayName("ARIA - OFB 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testOFB(int keyLength, int ivLength) {
        test.test_ofb(new ARIA(), keyLength, ivLength);
    }

    @DisplayName("ARIA - CFB 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCFB(int keyLength, int ivLength) {
        test.test_cfb(new ARIA(), keyLength, ivLength);
    }

    @DisplayName("ARIA - CTR 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCTR(int keyLength, int ivLength) {
        test.test_ctr(new ARIA(), keyLength, ivLength);
    }

    @DisplayName("ARIA - CTSECB 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}")
    @ValueSource(ints = {16, 24, 32})
    void testCTSECB(int keyLength) {
        test.test_ctsecb(new ARIA(), keyLength);
    }

    @DisplayName("ARIA - CTSCBC 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCTSCBC(int keyLength, int ivLength) {
        test.test_ctscbc(new ARIA(), keyLength, ivLength);
    }

    @DisplayName("ARIA - CCM 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,12", "24,12", "32,12"})
    void testCCM(int keyLength, int ivLength) {
        test.test_ccm(new ARIA(), keyLength, ivLength);
    }

    @DisplayName("ARIA - GCM 암호화 테스트")
    @ParameterizedTest(name = "ARIA keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testGCM(int keyLength, int ivLength) {
        test.test_gcm(new ARIA(), keyLength, ivLength);
    }
}

