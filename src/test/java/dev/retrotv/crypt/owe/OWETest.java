package dev.retrotv.crypt.owe;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.BaseEncode;
import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.random.SecurityStrength;
import org.junit.jupiter.api.RepetitionInfo;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class OWETest extends Log {
    protected static final Set<String> encryptedData = new HashSet<>();

    protected void parameterDataIsNullTest(OneWayEncryption owe) {
        Throwable exception = assertThrows(CryptFailException.class, () -> owe.encrypt((byte[]) null));

        log.info("예외 메시지: " + exception.getMessage());
        assertEquals("암호화 할 문자열 및 데이터는 null 일 수 없습니다.", exception.getMessage());
    }

    protected void parameterTextIsNullTest(OneWayEncryption owe) {
        Throwable exception = assertThrows(CryptFailException.class, () -> owe.encrypt(null, BaseEncode.HEX));

        log.info("예외 메시지: " + exception.getMessage());
        assertEquals("암호화 할 문자열 및 데이터는 null 일 수 없습니다.", exception.getMessage());
    }

    protected void parameterByteEncryptMatchTest(OneWayEncryption owe) {
        byte[] data = "The lazy dog jumps over the brown fox!".getBytes(StandardCharsets.UTF_8);
        byte[] salt = Salt.generate(SecurityStrength.HIGH, 20).getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = owe.encrypt(data, salt);

        assertTrue(owe.matches(data, salt, encryptedData));
    }

    protected void encryptedDataBase64EncodeTest(OneWayEncryption owe) {

    }

    protected void encryptWithoutSaltTest(OneWayEncryption owe, RepetitionInfo repetitionInfo) {
        log.info("암호화 알고리즘: " + owe.getClass().getSimpleName());

        String message = "The lazy dog jumps over the brown fox!";
        String encryptedMessage = owe.encrypt(message, BaseEncode.HEX);

        assertTrue(owe.matches(message, encryptedMessage));
        assertTrue(owe.matches(message, BaseEncode.HEX, encryptedMessage));
        assertTrue(checkBitLength(owe.getClass().getSimpleName(), (DatatypeConverter.parseHexBinary(encryptedMessage).length * 8)));

        encryptedData.add(encryptedMessage);
        if(repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
            log.info("마지막 테스트");
            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
            log.info("암호화 된 데이터 개수 : " + encryptedData.size());
            if(encryptedData.size() != 1) { fail(); }

            encryptedData.clear();
        }
    }

    protected void encryptWithSaltTest(OneWayEncryption owe, RepetitionInfo repetitionInfo) {
        log.info("암호화 알고리즘: " + owe.getClass().getSimpleName());

        String message = "The lazy dog jumps over the brown fox!";
        String salt = Salt.generate(SecurityStrength.HIGH, 20);
        String encryptedMessage = owe.encrypt(message, salt, BaseEncode.HEX);

        log.info("암호화 된 메시지: " + encryptedMessage);
        log.info("암호화 된 메시지 bit 길이: " + (DatatypeConverter.parseHexBinary(encryptedMessage).length * 8));

        assertTrue(owe.matches(message, salt, encryptedMessage));
        assertTrue(owe.matches(message, salt, BaseEncode.HEX, encryptedMessage));
        assertTrue(checkBitLength(owe.getClass().getSimpleName(), (DatatypeConverter.parseHexBinary(encryptedMessage).length * 8)));

        encryptedData.add(encryptedMessage);
        if(repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
            log.info("마지막 테스트");
            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
            log.info("암호화 된 데이터 개수 : " + encryptedData.size());
            if(repetitionInfo.getTotalRepetitions() != encryptedData.size()) { fail(); }

            encryptedData.clear();
        }
    }

    private boolean checkBitLength(String algorithm, int length) {
        switch (algorithm) {
            case "CRC32":
                return length == 32;

            case "MD2":
            case "MD5":
                return length == 128;

            case "SHA1":
                return length == 160;

            case "SHA224":
            case "SHA512224":
                return length == 224;

            case "SHA256":
            case "SHA512256":
                return length == 256;

            case "SHA384":
                return length == 384;

            case "SHA512":
                return length == 512;
        }

        return false;
    }
}
