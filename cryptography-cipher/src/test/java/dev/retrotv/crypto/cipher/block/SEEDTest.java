package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.block.algorithm.SEED;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class SEEDTest {
    private final BlockChiperTest test = new BlockChiperTest();

    @DisplayName("SEED 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}")
    @ValueSource(ints = {16})
    void testSEED(int keyLength) {
        test.test_ecb(new SEED(), keyLength);
    }

    @DisplayName("SEED - CBC 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16"})
    void testCBC(int keyLength, int ivLength) {
        test.test_cbc(new SEED(), keyLength, ivLength);
    }

    @DisplayName("SEED - OFB 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16"})
    void testOFB(int keyLength, int ivLength) {
        test.test_ofb(new SEED(), keyLength, ivLength);
    }

    @DisplayName("SEED - CFB 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16"})
    void testCFB(int keyLength, int ivLength) {
        test.test_cfb(new SEED(), keyLength, ivLength);
    }

    @DisplayName("SEED - CTR 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16"})
    void testCTR(int keyLength, int ivLength) {
        test.test_ctr(new SEED(), keyLength, ivLength);
    }

    @DisplayName("SEED - CTSECB 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}")
    @ValueSource(ints = {16})
    void testCTSECB(int keyLength) {
        test.test_ctsecb(new SEED(), keyLength);
    }

    @DisplayName("SEED - CTSCBC 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16"})
    void testCTSCBC(int keyLength, int ivLength) {
        test.test_ctscbc(new SEED(), keyLength, ivLength);
    }

    @DisplayName("SEED - CCM 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,12"})
    void testCCM(int keyLength, int ivLength) {
        test.test_ccm(new SEED(), keyLength, ivLength);
    }

    @DisplayName("SEED - GCM 암호화 테스트")
    @ParameterizedTest(name = "SEED keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16"})
    void testGCM(int keyLength, int ivLength) {
        test.test_gcm(new SEED(), keyLength, ivLength);
    }
}

