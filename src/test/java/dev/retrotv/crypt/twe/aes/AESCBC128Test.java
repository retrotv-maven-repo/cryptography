package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
public class AESCBC128Test extends AESTest {

    @Test
    @DisplayName("AES/CBC IV 생성 테스트")
    void IVGenerateTest() throws CryptFailException {
        encryptedDataWithIVTest(new AESCBC128());
    }

    @DisplayName("AES-128 CBC 알고리즘 암복호화 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void AESCBC128EncryptDecryptTest(RepetitionInfo repetitionInfo) throws CryptFailException {
        TwoWayEncryption twe = new AESCBC128();
        encryptDecryptTest(twe, repetitionInfo);
    }
}
