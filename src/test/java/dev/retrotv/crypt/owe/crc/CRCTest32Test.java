package dev.retrotv.crypt.owe.crc;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.OWETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.util.Objects;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CRCTest32Test extends Log {

    protected final URL resource = this.getClass().getClassLoader().getResource("Usb_connectors.JPG");
    protected final URL resource2 = this.getClass().getClassLoader().getResource("Usb_connectors2.JPG");

    @Test
    @DisplayName("CRC32 hash 테스트")
    void crc32Hash() throws IOException {
        File file;
        try {
            file = new File(Objects.requireNonNull(resource).toURI());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file.toPath()))) {
            byte[] fileData = new byte[(int) file.length()];
            dis.readFully(fileData);

            Checksum fc = new CRC32();
            String hash = fc.encode(fileData);

            log.info("hash 값: " + hash);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 예상치 못한 오류가 발생했습니다.");
        }
    }
}
