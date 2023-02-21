package dev.retrotv.crypt.owe.crc;

import dev.retrotv.crypt.OneWayEncryption;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;

public class CRC32 implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(data);

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(crc32.getValue());

        // 앞에 0이 패딩되는 부분을 무시하고 뒤의 8자리만 잘라낸다
        return DatatypeConverter.parseHexBinary(DatatypeConverter.printHexBinary(buffer.array()).substring(8));
    }
}
