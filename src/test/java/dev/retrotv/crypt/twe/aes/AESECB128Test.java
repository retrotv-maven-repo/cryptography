package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.TwoWayEncryption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(value = PER_CLASS)
public class AESECB128Test extends AESTest {

    @DisplayName("AES-128 ECB 알고리즘 암복호화 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    void AESECB128EncryptDecryptTest(RepetitionInfo repetitionInfo) {
        TwoWayEncryption twe = new AESECB128();
        encryptDecryptTest(twe, repetitionInfo);
    }
}
