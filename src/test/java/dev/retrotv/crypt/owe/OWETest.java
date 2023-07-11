package dev.retrotv.crypt.owe;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.owe.crc.CRC32;
import dev.retrotv.crypt.owe.md.*;
import dev.retrotv.crypt.owe.sha.*;
import dev.retrotv.enums.HashAlgorithm;
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

    protected void fileHashTest(HashAlgorithm algorithm) throws IOException {
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

    protected void fileHashMatchesTest(Checksum checksum, HashAlgorithm algorithm) throws IOException {
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

    private String hash(HashAlgorithm algorithm, byte[] fileData) {
        switch (algorithm) {
            case CRC32: {
                Checksum checksum = new CRC32();
                return checksum.hash(fileData);
            }

            case MD2: {
                Checksum checksum = new MD2();
                return checksum.hash(fileData);
            }

            case MD5: {
                Checksum checksum = new MD5();
                return checksum.hash(fileData);
            }

            case SHA1:  {
                Checksum checksum = new SHA1();
                return checksum.hash(fileData);
            }

            case SHA224: {
                Checksum checksum = new SHA224();
                return checksum.hash(fileData);
            }

            case SHA256:  {
                Checksum checksum = new SHA256();
                return checksum.hash(fileData);
            }

            case SHA384: {
                Checksum checksum = new SHA384();
                return checksum.hash(fileData);
            }

            case SHA512: {
                Checksum checksum = new SHA512();
                return checksum.hash(fileData);
            }

            case SHA512224: {
                Checksum checksum = new SHA512224();
                return checksum.hash(fileData);
            }

            case SHA512256: {
                Checksum checksum = new SHA512256();
                return checksum.hash(fileData);
            }

            default: return null;
        }
    }

    private String getHash(HashAlgorithm algorithm) throws IOException {
        JSONObject jsonObject = new JSONObject(readJson());
        JSONObject file1 = jsonObject.getJSONObject("checksum_test_file");

        switch (algorithm) {
            case CRC32: return file1.getString(HashAlgorithm.CRC32.label());
            case MD2: return file1.getString(HashAlgorithm.MD2.label());
            case MD5: return file1.getString(HashAlgorithm.MD5.label());
            case SHA1: return file1.getString(HashAlgorithm.SHA1.label());
            case SHA224: return file1.getString(HashAlgorithm.SHA224.label());
            case SHA256: return file1.getString(HashAlgorithm.SHA256.label());
            case SHA384: return file1.getString(HashAlgorithm.SHA384.label());
            case SHA512: return file1.getString(HashAlgorithm.SHA512.label());
            case SHA512224: return file1.getString(HashAlgorithm.SHA512224.label());
            case SHA512256: return file1.getString(HashAlgorithm.SHA512256.label());
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
}
