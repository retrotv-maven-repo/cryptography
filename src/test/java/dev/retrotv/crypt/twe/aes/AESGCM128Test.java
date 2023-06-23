package dev.retrotv.crypt.twe.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.TwoWayEncryption;

public class AESGCM128Test extends AESTest {

    @DisplayName("AES-128 CBC 알고리즘 암복호화 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void AESCBC128EncryptDecryptTest(RepetitionInfo repetitionInfo) throws CryptFailException {
        TwoWayEncryption twe = new AESGCM128();
        encryptDecryptTest(twe, repetitionInfo);
    }
}
