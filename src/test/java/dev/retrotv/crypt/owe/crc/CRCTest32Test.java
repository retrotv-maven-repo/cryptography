package dev.retrotv.crypt.owe.crc;

import dev.retrotv.crypt.owe.OneWayEncryption;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

public class CRCTest32Test extends OWETest {

    @Test
    @DisplayName("암호화 데이터 null 체크")
    void dataNullCheck() {
        OneWayEncryption owe = new CRC32();
        parameterDataIsNullTest(owe);
    }

    @Test
    @DisplayName("암호화 문자열 null 체크")
    void textNullCheck() {
        OneWayEncryption owe = new CRC32();
        parameterTextIsNullTest(owe);
    }

    @Test
    @DisplayName("base64 인코딩 테스트")
    void base64EncodeTest() {
        OneWayEncryption owe = new CRC32();
        encryptedDataBase64EncodeTest(owe);
    }

    @RepeatedTest(100)
    @DisplayName("CRC-32 알고리즘 암호화 테스트")
    void crc32EncryptTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new CRC32();
        encryptWithoutSaltTest(owe, repetitionInfo);
    }

    @RepeatedTest(100)
    @DisplayName("CRC-32 알고리즘 + 소금치기 암호화 테스트")
    void crc32EncryptWithSaltTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new CRC32();
        encryptWithSaltTest(owe, repetitionInfo);
    }
}
