package dev.retrotv.crypto.owe.hash.crc;

import dev.retrotv.crypto.owe.hash.Hash;
import dev.retrotv.crypto.owe.hash.Checksum;
import dev.retrotv.crypto.owe.hash.PasswordWithSalt;
import dev.retrotv.utils.EncodeUtil;
import lombok.NonNull;

import java.nio.ByteBuffer;

/**
 * CRC-32 알고리즘으로 암호화 하기 위한 {@link Checksum}, {@link PasswordWithSalt} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class CRC32 extends Hash {

    @Override
    public String hash(@NonNull byte[] data) {
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(data);

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(crc32.getValue());

        // 앞에 0이 패딩되는 부분을 무시하고 뒤의 8자리만 잘라낸다
        return EncodeUtil.binaryToHex(buffer.array()).substring(8);

    }
}
