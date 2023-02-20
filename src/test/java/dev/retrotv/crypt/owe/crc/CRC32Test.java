package dev.retrotv.crypt.owe.crc;

import dev.retrotv.common.Log;
import dev.retrotv.crypt.Encode;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class CRC32Test extends Log {

    @Test
    void Test() {
        String message = "The lazy dog jumps over the brown fox!";

        CRC32 crc32 = new CRC32();
        String encryptedData = crc32.encrypt(message, Encode.HEX);

        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(message.getBytes(StandardCharsets.UTF_8));
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(crc.getValue());
        log.info("" + DatatypeConverter.printHexBinary(buffer.array()));

        log.info(""+ encryptedData);
    }
}
