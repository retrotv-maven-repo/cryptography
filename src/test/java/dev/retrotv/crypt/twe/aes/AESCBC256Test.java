package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
public class AESCBC256Test extends AESTest {

    @Test
    @DisplayName("AES/CBC IV 생성 테스트")
    void IVGenerateTest() throws CryptFailException, KeyGenerateException {
        encryptedDataWithIVTest(new AESCBC256());
    }

    @DisplayName("AES-256 CBC 알고리즘 암복호화 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void AESCBC256EncryptDecryptTest(RepetitionInfo repetitionInfo) throws CryptFailException {
        TwoWayEncryption twe = new AESCBC256();
        encryptDecryptTest(twe, repetitionInfo);
    }
}
