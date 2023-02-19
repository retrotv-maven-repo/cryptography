package dev.retrotv.crypt.md;

import dev.retrotv.crypt.OneWayEncryption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

public class MD5Test extends MDTest {

    @RepeatedTest(100)
    @DisplayName("MD5 알고리즘 암호화 테스트")
    void md5EncryptTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new MD5();
        encryptWithoutSaltTest(owe, repetitionInfo);
    }

    @RepeatedTest(100)
    @DisplayName("MD5 알고리즘 + 소금치기 암호화 테스트")
    void md5EncryptWithSaltTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new MD5();
        encryptWithSaltTest(owe, repetitionInfo);
    }
}
