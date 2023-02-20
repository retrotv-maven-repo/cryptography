package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.OneWayEncryption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import java.util.logging.Logger;

public class SHA224Test extends SHATest {
    private static final Logger log = Logger.getGlobal();

    @RepeatedTest(100)
    @DisplayName("SHA-224 알고리즘 암호화 테스트")
    void sha224EncryptTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new SHA224();
        encryptWithoutSaltTest(owe, repetitionInfo);
    }

    @RepeatedTest(100)
    @DisplayName("SHA-224 알고리즘 + 소금치기 암호화 테스트")
    void sha224EncryptWithSaltTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new SHA224();
        encryptWithSaltTest(owe, repetitionInfo);
    }
}
