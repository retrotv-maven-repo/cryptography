package dev.retrotv.crypt.owe.crc;

import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.owe.md.MD2;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CRCTest32Test extends CRCTest {

    @RepeatedTest(100)
    @DisplayName("MD2 알고리즘 암호화 테스트")
    void md2EncryptTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new CRC32();
        encryptWithoutSaltTest(owe, repetitionInfo);
    }

    @RepeatedTest(100)
    @DisplayName("MD2 알고리즘 + 소금치기 암호화 테스트")
    void md2EncryptWithSaltTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new CRC32();
        encryptWithSaltTest(owe, repetitionInfo);
    }
}
