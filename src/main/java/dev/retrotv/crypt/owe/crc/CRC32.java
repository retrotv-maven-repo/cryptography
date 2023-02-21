package dev.retrotv.crypt.owe.crc;

import dev.retrotv.crypt.OneWayEncryption;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;

public class CRC32 implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(data);

        return DatatypeConverter.parseHexBinary(Long.toHexString(crc32.getValue()));
    }
}
