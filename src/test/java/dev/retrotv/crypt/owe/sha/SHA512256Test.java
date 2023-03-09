package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.owe.OneWayEncryption;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

public class SHA512256Test extends OWETest {

    @Test
    @DisplayName("암호화 데이터 null 체크")
    void dataNullCheck() {
        OneWayEncryption owe = new SHA512256();
        parameterDataIsNullTest(owe);
    }

    @Test
    @DisplayName("암호화 문자열 null 체크")
    void textNullCheck() {
        OneWayEncryption owe = new SHA512256();
        parameterTextIsNullTest(owe);
    }

    @Test
    @DisplayName("base64 인코딩 테스트")
    void base64EncodeTest() {
        OneWayEncryption owe = new SHA512256();
        encryptedDataBase64EncodeTest(owe);
    }

    @RepeatedTest(100)
    @DisplayName("SHA-512/256 알고리즘 암호화 테스트")
    void sha512EncryptTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new SHA512256();
        encryptWithoutSaltTest(owe, repetitionInfo);
    }

    @RepeatedTest(100)
    @DisplayName("SHA-512/256 알고리즘 + 소금치기 암호화 테스트")
    void sha512EncryptWithSaltTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new SHA512256();
        encryptWithSaltTest(owe, repetitionInfo);
    }
}
