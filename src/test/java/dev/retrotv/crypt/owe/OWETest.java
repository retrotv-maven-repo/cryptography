package dev.retrotv.crypt.owe;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.crc.CRC32;
import dev.retrotv.crypt.owe.md.MD5;
import dev.retrotv.crypt.owe.sha.*;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

public class OWETest extends Log {
    protected final String PASSWORD = "The quick brown fox jumps over the lazy dog";
    protected final URL RESOURCE = this.getClass().getClassLoader().getResource("Usb_connectors.JPG");
    protected final URL RESOURCE2 = this.getClass().getClassLoader().getResource("Usb_connectors2.JPG");

    protected void fileHash(Algorithm algorithm) throws IOException {
        File file;
        byte[] fileData;

        try {
            file = new File(Objects.requireNonNull(RESOURCE).toURI());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file.toPath()))) {
            fileData = new byte[(int) file.length()];
            dis.readFully(fileData);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 예상치 못한 오류가 발생했습니다.");
        }

        assertEquals(getHash(algorithm), hash(algorithm, fileData));
    }

    protected void fileHashMatchs(Checksum checksum, Algorithm algorithm) throws IOException {
        File file;
        byte[] fileData;

        try {
            file = new File(Objects.requireNonNull(RESOURCE).toURI());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file.toPath()))) {
            fileData = new byte[(int) file.length()];
            dis.readFully(fileData);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 예상치 못한 오류가 발생했습니다.");
        }

        assertTrue(checksum.matches(fileData, getHash(algorithm)));
    }

    protected void passwordEncrypt(Password password) {
        String encryptedPassword = password.encode(PASSWORD);

        assertNotEquals(PASSWORD, encryptedPassword);
        assertTrue(password.matches(PASSWORD, encryptedPassword));
    }

    private String hash(Algorithm algorithm, byte[] fileData) {
        switch (algorithm) {
            case CRC32: {
                Checksum checksum = new CRC32();
                return checksum.encode(fileData);
            }

            case MD5: {
                Checksum checksum = new MD5();
                return checksum.encode(fileData);
            }

            case SHA1:  {
                Checksum checksum = new SHA1();
                return checksum.encode(fileData);
            }

            case SHA224: {
                Checksum checksum = new SHA224();
                return checksum.encode(fileData);
            }

            case SHA256:  {
                Checksum checksum = new SHA256();
                return checksum.encode(fileData);
            }

            case SHA384: {
                Checksum checksum = new SHA384();
                return checksum.encode(fileData);
            }

            case SHA512: {
                Checksum checksum = new SHA512();
                return checksum.encode(fileData);
            }

            case SHA512224: {
                Checksum checksum = new SHA512224();
                return checksum.encode(fileData);
            }

            case SHA512256: {
                Checksum checksum = new SHA512256();
                return checksum.encode(fileData);
            }

            default: return null;
        }
    }

    private String getHash(Algorithm algorithm) {
        switch (algorithm) {
            case CRC32: return "bbaa4ecc";
            case MD5: return "50612b57c95b3a5168af0803183e11a6";
            case SHA1: return "ebea6f522d1fca234bcf8fe67bcbe36b16c76a08";
            case SHA224: return "b1958b147149aa43da0b660359be731c939175a40bf7595641daeb9f";
            case SHA256: return "77f0dff93e642bf30107409b3c2bf091e68abbcd72e4088644fa4af74bcb03ef";
            case SHA384: return "8f0cf4885b8d66738c11e060889a50559cb02a41c47680bbbe4dbf83bf80b9811ccf676c8129856d0448371117f4eff2";
            case SHA512: return "cc4b339254aa795cf37cf9bfbe03c517f4ccca68a957da247e4740bbcfa52eab11578655a6d6686d406f8d78cb208ec41ea236a2c8670ea21cc9f500302e9792";
            case SHA512224: return "909e7bfd4460eb945558dc28e9e59cee80c7cba836cc2bd69dba1a45";
            case SHA512256: return "3e86050d3a99a5ad768cdfd75acd100a7ff287d1927fb3c2bc528874f02e9a0d";
            default: return null;
        }
    }

//    protected static final Set<String> encryptedData = new HashSet<>();
//
//    protected void parameterDataIsNullTest(OneWayEncryption owe) {
//        Throwable exception = assertThrows(CryptFailException.class, () -> owe.encrypt((byte[]) null));
//
//        log.info("예외 메시지: " + exception.getMessage());
//        assertEquals("암호화 할 문자열 및 데이터는 null 일 수 없습니다.", exception.getMessage());
//    }
//
//    protected void parameterTextIsNullTest(OneWayEncryption owe) {
//        Throwable exception = assertThrows(CryptFailException.class, () -> owe.encrypt((String) null, EncodeFormat.HEX));
//
//        log.info("예외 메시지: " + exception.getMessage());
//        assertEquals("암호화 할 문자열 및 데이터는 null 일 수 없습니다.", exception.getMessage());
//    }
//
//    protected void encryptedDataBase64EncodeTest(OneWayEncryption owe) {
//        String message = "The lazy dog jumps over the brown fox!";
//        String encryptedMessage = owe.encrypt(message, EncodeFormat.BASE64);
//
//        log.info("암호화 된 메시지: " + encryptedMessage);
//
//        assertTrue(owe.matches(message, EncodeFormat.BASE64, encryptedMessage));
//    }
//
//    protected void encryptWithoutSaltTest(OneWayEncryption owe, RepetitionInfo repetitionInfo) {
//        log.info("암호화 알고리즘: " + owe.getClass().getSimpleName());
//
//        String message = "The lazy dog jumps over the brown fox!";
//        String encryptedMessage = owe.encrypt(message, EncodeFormat.HEX);
//
//        assertTrue(owe.matches(message, encryptedMessage));
//        assertTrue(owe.matches(message, EncodeFormat.HEX, encryptedMessage));
//        assertTrue(checkBitLength(owe.getClass().getSimpleName(), (DatatypeConverter.parseHexBinary(encryptedMessage).length * 8)));
//
//        encryptedData.add(encryptedMessage);
//        if(repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
//            log.info("마지막 테스트");
//            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
//            log.info("암호화 된 데이터 개수 : " + encryptedData.size());
//            if(encryptedData.size() != 1) { fail(); }
//
//            encryptedData.clear();
//        }
//    }
//
//    protected void encryptWithSaltTest(OneWayEncryption owe, RepetitionInfo repetitionInfo) {
//        log.info("암호화 알고리즘: " + owe.getClass().getSimpleName());
//
//        String message = "The lazy dog jumps over the brown fox!";
//        String salt = RandomValue.generate(SecurityStrength.HIGH, 20);
//        String encryptedMessage = owe.encrypt(message, salt, EncodeFormat.HEX);
//
//        log.info("암호화 된 메시지: " + encryptedMessage);
//        log.info("암호화 된 메시지 bit 길이: " + (DatatypeConverter.parseHexBinary(encryptedMessage).length * 8));
//
//        assertTrue(owe.matches(message, salt, encryptedMessage));
//        assertTrue(owe.matches(message, salt, EncodeFormat.HEX, encryptedMessage));
//        assertTrue(checkBitLength(owe.getClass().getSimpleName(), (DatatypeConverter.parseHexBinary(encryptedMessage).length * 8)));
//
//        encryptedData.add(encryptedMessage);
//        if(repetitionInfo.getCurrentRepetition() == repetitionInfo.getTotalRepetitions()) {
//            log.info("마지막 테스트");
//            log.info("총 테스트 횟수: " + repetitionInfo.getCurrentRepetition());
//            log.info("암호화 된 데이터 개수 : " + encryptedData.size());
//            if(repetitionInfo.getTotalRepetitions() != encryptedData.size()) { fail(); }
//
//            encryptedData.clear();
//        }
//    }
//
//    private boolean checkBitLength(String algorithm, int length) {
//        switch (algorithm) {
//            case "CRC32":
//                return length == 32;
//
//            case "MD2":
//            case "MD5":
//                return length == 128;
//
//            case "SHA1":
//                return length == 160;
//
//            case "SHA224":
//            case "SHA512224":
//                return length == 224;
//
//            case "SHA256":
//            case "SHA512256":
//                return length == 256;
//
//            case "SHA384":
//                return length == 384;
//
//            case "SHA512":
//                return length == 512;
//        }
//
//        return false;
//    }
}
