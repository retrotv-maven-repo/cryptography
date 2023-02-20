package dev.retrotv.crypt.owe.sha;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.Encode;
import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.owe.Salt;
import dev.retrotv.crypt.random.SecurityStrength;
import org.junit.jupiter.api.RepetitionInfo;

import javax.xml.bind.DatatypeConverter;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class SHATest extends Log {
    protected static final Set<String> encryptedData = new HashSet<>();

    void encryptWithoutSaltTest(OneWayEncryption owe, RepetitionInfo repetitionInfo) {
        log.info("암호화 알고리즘: " + owe.getClass().getSimpleName());

        String message = "The lazy dog jumps over the brown fox!";
        String encryptedMessage = owe.encrypt(message, Encode.HEX);

        log.info("암호화 된 메시지: " + encryptedMessage);
        log.info("암호화 된 메시지 bit 길이: " + (DatatypeConverter.parseHexBinary(encryptedMessage).length * 8));

        assertTrue(owe.matches(message, Encode.HEX, encryptedMessage));
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

    void encryptWithSaltTest(OneWayEncryption owe, RepetitionInfo repetitionInfo) {
        log.info("암호화 알고리즘: " + owe.getClass().getSimpleName());

        String message = "The lazy dog jumps over the brown fox!";
        String salt = Salt.generate(SecurityStrength.HIGH, 20);
        String encryptedMessage = owe.encrypt(message, salt, Encode.HEX);

        log.info("암호화 된 메시지: " + encryptedMessage);
        log.info("암호화 된 메시지 bit 길이: " + (DatatypeConverter.parseHexBinary(encryptedMessage).length * 8));

        assertTrue(owe.matches(message, salt, Encode.HEX, encryptedMessage));
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

    boolean checkBitLength(String algorithm, int length) {
        switch (algorithm) {
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
