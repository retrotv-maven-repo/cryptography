package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.twe.TwoWayEncryption;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
public class AESCBC192Test extends AESTest {

    @Test
    @DisplayName("AES/CBC IV 생성 테스트")
    void IVGenerateTest() {
        encryptedDataWithIVTest(new AESCBC192());
    }

    @DisplayName("AES-192 CBC 알고리즘 암복호화 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void AESCBC192EncryptDecryptTest(RepetitionInfo repetitionInfo) {
        TwoWayEncryption twe = new AESCBC192();
        encryptDecryptTest(twe, repetitionInfo);
    }
}
