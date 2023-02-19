package dev.retrotv.crypt.sha;

import dev.retrotv.crypt.OneWayEncryption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import java.util.logging.Logger;

public class SHA256Test extends SHATest{
    private static final Logger log = Logger.getGlobal();

    @RepeatedTest(100)
    @DisplayName("SHA-256 알고리즘 암호화 테스트")
    void sha256EncryptTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new SHA256();
        encryptWithoutSaltTest(owe, repetitionInfo);
    }

    @RepeatedTest(100)
    @DisplayName("SHA-256 알고리즘 + 소금치기 암호화 테스트")
    void sha256EncryptWithSaltTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new SHA256();
        encryptWithSaltTest(owe, repetitionInfo);
    }
}
