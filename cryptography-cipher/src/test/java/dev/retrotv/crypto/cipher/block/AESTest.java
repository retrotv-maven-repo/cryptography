package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.block.algorithm.AES;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class AESTest {
    private final BlockChiperTest test = new BlockChiperTest();

    @DisplayName("AES - ECB 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}")
    @ValueSource(ints = {16, 24, 32})
    void testECB(int keyLength) {
        test.test_ecb(new AES(), keyLength);
    }

    @DisplayName("AES - CBC 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCBC(int keyLength, int ivLength) {
        test.test_cbc(new AES(), keyLength, ivLength);
    }

    @DisplayName("AES - OFB 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testOFB(int keyLength, int ivLength) {
        test.test_ofb(new AES(), keyLength, ivLength);
    }

    @DisplayName("AES - CFB 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCFB(int keyLength, int ivLength) {
        test.test_cfb(new AES(), keyLength, ivLength);
    }

    @DisplayName("AES - CTR 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCTR(int keyLength, int ivLength) {
        test.test_ctr(new AES(), keyLength, ivLength);
    }

    @DisplayName("AES - CTSECB 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}")
    @ValueSource(ints = {16, 24, 32})
    void testCTSECB(int keyLength) {
        test.test_ctsecb(new AES(), keyLength);
    }

    @DisplayName("AES - CTSCBC 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testCTSCBC(int keyLength, int ivLength) {
        test.test_ctscbc(new AES(), keyLength, ivLength);
    }

    @DisplayName("AES - CCM 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,12", "24,12", "32,12"})
    void testCCM(int keyLength, int ivLength) {
        test.test_ccm(new AES(), keyLength, ivLength);
    }

    @DisplayName("AES - GCM 암호화 테스트")
    @ParameterizedTest(name = "AES keyLength: {0}, ivLength: {1}")
    @CsvSource({"16,16", "24,16", "32,16"})
    void testGCM(int keyLength, int ivLength) {
        test.test_gcm(new AES(), keyLength, ivLength);
    }
}

