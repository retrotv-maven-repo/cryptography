package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
public class AESECB192Test extends AESTest {

    @DisplayName("AES-192 ECB 알고리즘 암복호화 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void AESECB192EncryptDecryptTest(RepetitionInfo repetitionInfo) throws CryptFailException {
        TwoWayEncryption twe = new AESECB192();
        encryptDecryptTest(twe, repetitionInfo);
    }
}
