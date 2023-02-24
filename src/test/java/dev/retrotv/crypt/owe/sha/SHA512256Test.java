package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SHA512256Test extends OWETest {

    @Test
    @DisplayName("암호화 데이터 null 체크")
    void nullCheck() {
        Throwable exception = assertThrows(CryptFailException.class, () -> {
            OneWayEncryption owe = new SHA512256();
            owe.encrypt((byte[]) null);
        });

        log.info("예외 메시지: " + exception.getMessage());
        assertEquals("암호화 할 문자열 및 데이터는 null 일 수 없습니다.", exception.getMessage());
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
