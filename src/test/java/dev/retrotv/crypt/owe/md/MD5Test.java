package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class MD5Test extends OWETest {

    @Test
    @DisplayName("암호화 데이터 null 체크")
    void nullCheck() {
        Throwable exception = assertThrows(CryptFailException.class, () -> {
            OneWayEncryption owe = new MD5();
            owe.encrypt((byte[]) null);
        });

        log.info("예외 메시지: " + exception.getMessage());
        assertEquals("암호화 할 문자열 및 데이터는 null 일 수 없습니다.", exception.getMessage());
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
