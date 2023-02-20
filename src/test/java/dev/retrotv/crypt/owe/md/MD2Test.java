package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.OneWayEncryption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

public class MD2Test extends MDTest {

    @RepeatedTest(100)
    @DisplayName("MD2 알고리즘 암호화 테스트")
    void md2EncryptTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new MD2();
        encryptWithoutSaltTest(owe, repetitionInfo);
    }

    @RepeatedTest(100)
    @DisplayName("MD2 알고리즘 + 소금치기 암호화 테스트")
    void md2EncryptWithSaltTest(RepetitionInfo repetitionInfo) {
        OneWayEncryption owe = new MD2();
        encryptWithSaltTest(owe, repetitionInfo);
    }
}
