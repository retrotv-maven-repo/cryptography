package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.block.algorithm.Serpent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class SerpentTest {
    private final BlockChiperTest test = new BlockChiperTest();

    @DisplayName("Serpent 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}")
    @ValueSource(ints = {16, 24, 32})
    void testSerpent(int keyLength) {
        test.test_ecb(new Serpent(), keyLength);
    }

    @DisplayName("Serpent - CBC 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCBC(int keyLength, int ivLength) {
        test.test_cbc(new Serpent(), keyLength, ivLength);
    }

    @DisplayName("Serpent - OFB 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testOFB(int keyLength, int ivLength) {
        test.test_ofb(new Serpent(), keyLength, ivLength);
    }

    @DisplayName("Serpent - CFB 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCFB(int keyLength, int ivLength) {
        test.test_cfb(new Serpent(), keyLength, ivLength);
    }

    @DisplayName("Serpent - CTR 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCTR(int keyLength, int ivLength) {
        test.test_ctr(new Serpent(), keyLength, ivLength);
    }

    @DisplayName("Serpent - CTSECB 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}")
    @ValueSource(ints = {16, 24, 32})
    void testCTSECB(int keyLength) {
        test.test_ctsecb(new Serpent(), keyLength);
    }

    @DisplayName("Serpent - CTSCBC 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCTSCBC(int keyLength, int ivLength) {
        test.test_ctscbc(new Serpent(), keyLength, ivLength);
    }

    @DisplayName("Serpent - CCM 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,12", "24,12", "32,12"})
    void testCCM(int keyLength, int ivLength) {
        test.test_ccm(new Serpent(), keyLength, ivLength);
    }

    @DisplayName("Serpent - GCM 암호화 테스트")
    @ParameterizedTest(name = "Serpent keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testGCM(int keyLength, int ivLength) {
        test.test_gcm(new Serpent(), keyLength, ivLength);
    }
}

