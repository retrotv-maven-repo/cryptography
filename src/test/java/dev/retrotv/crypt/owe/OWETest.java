package dev.retrotv.crypt.owe;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.crc.CRC32;
import dev.retrotv.crypt.owe.md.*;
import dev.retrotv.crypt.owe.sha.*;
import org.json.JSONObject;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

public class OWETest extends Log {
    protected final String PASSWORD = "The quick brown fox jumps over the lazy dog";
    protected  final URL CHECKSUM = this.getClass().getClassLoader().getResource("checksum");
    protected final URL RESOURCE = this.getClass().getClassLoader().getResource("checksum_test_file.txt");
    protected final URL RESOURCE2 = this.getClass().getClassLoader().getResource("checksum_test_file2.txt");

    protected void fileHashTest(Algorithm algorithm) throws IOException {
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

    protected void fileHashMatchesTest(Checksum checksum, Algorithm algorithm) throws IOException {
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

    protected void fileMatchesTest(Checksum checksum) throws IOException {
        if (RESOURCE != null && RESOURCE2 != null) {
            assertTrue(checksum.matches(new File(RESOURCE.getFile()), new File(RESOURCE2.getFile())));
        } else {
            fail();
        }
    }

    protected void passwordEncryptAndMatchesTest(Password password) {
        String encryptedPassword = password.encode(PASSWORD);

        log.info(encryptedPassword);

        assertNotEquals(PASSWORD, encryptedPassword);
        assertTrue(password.matches(PASSWORD, encryptedPassword));
    }

    private String hash(Algorithm algorithm, byte[] fileData) {
        switch (algorithm) {
            case CRC32: {
                Checksum checksum = new CRC32();
                return checksum.encode(fileData);
            }

            case MD2: {
                Checksum checksum = new MD2();
                return checksum.encode(fileData);
            }

            case MD4: {
                Checksum checksum = new MD4();
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

    private String getHash(Algorithm algorithm) throws IOException {
        JSONObject jsonObject = new JSONObject(readJson());
        JSONObject file1 = jsonObject.getJSONObject("checksum_test_file");

        switch (algorithm) {
            case CRC32: return file1.getString(Algorithm.CRC32.label());
            case MD2: return file1.getString(Algorithm.MD2.label());
            case MD4: return file1.getString(Algorithm.MD4.label());
            case MD5: return file1.getString(Algorithm.MD5.label());
            case SHA1: return file1.getString(Algorithm.SHA1.label());
            case SHA224: return file1.getString(Algorithm.SHA224.label());
            case SHA256: return file1.getString(Algorithm.SHA256.label());
            case SHA384: return file1.getString(Algorithm.SHA384.label());
            case SHA512: return file1.getString(Algorithm.SHA512.label());
            case SHA512224: return file1.getString(Algorithm.SHA512224.label());
            case SHA512256: return file1.getString(Algorithm.SHA512256.label());
            default: return null;
        }
    }

    private String readJson() throws IOException {
        if (CHECKSUM == null) {
            throw new IOException();
        }

        String json;

        try(BufferedReader reader = new BufferedReader(new FileReader(CHECKSUM.getFile()))) {
            StringBuilder sb = new StringBuilder();
            String line = reader.readLine();

            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = reader.readLine();
            }
            json = sb.toString();
        }

        log.info(json);

        return json;
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
