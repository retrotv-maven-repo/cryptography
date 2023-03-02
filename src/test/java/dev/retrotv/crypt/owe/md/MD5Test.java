package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class MD5Test extends OWETest {

    @Test
    @DisplayName("암호화 데이터 null 체크")
    void dataNullCheck() {
        OneWayEncryption owe = new MD5();
        parameterDataIsNullTest(owe);
    }

    @Test
    @DisplayName("암호화 문자열 null 체크")
    void textNullCheck() {
        OneWayEncryption owe = new MD5();
        parameterTextIsNullTest(owe);
    }

    @Test
    @DisplayName("byte[] 데이터형 테스트")
    void byteEncryptMatchTest() {
        OneWayEncryption owe = new MD5();
        parameterByteEncryptMatchTest(owe);
    }

    @Test
    @DisplayName("base64 인코딩 테스트")
    void base64EncodeTest() {
        OneWayEncryption owe = new MD5();
        encryptedDataBase64EncodeTest(owe);
    }

    @Test
    @DisplayName("동일 결과 체크")
    void sameResult() throws Exception {
        String message = "The lazy dog jumps over the brown fox!";

        OneWayEncryption owe = new MD5();
        String encryptMessage = owe.encrypt(message);
        byte[] encryptData = owe.encrypt(message.getBytes(StandardCharsets.UTF_8));

        owe.matches(encryptMessage, DatatypeConverter.printHexBinary(encryptData).toLowerCase());
    }

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
