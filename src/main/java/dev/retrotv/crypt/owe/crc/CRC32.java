package dev.retrotv.crypt.owe.crc;

import dev.retrotv.utils.EncodeUtil;
import lombok.NonNull;
import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.PasswordWithSalt;
import dev.retrotv.utils.CommonMessageUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

/**
 * CRC-32 알고리즘으로 암호화 하기 위한 {@link Checksum}, {@link PasswordWithSalt} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class CRC32 implements Checksum, PasswordWithSalt {
    private static final Logger log = LogManager.getLogger();
    private static final CommonMessageUtil commonMessageUtil = new CommonMessageUtil();

    @Override
    public String encode(@NonNull byte[] data) {
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(data);

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(crc32.getValue());

        // 앞에 0이 패딩되는 부분을 무시하고 뒤의 8자리만 잘라낸다
        return EncodeUtil.binaryToHex(buffer.array()).substring(8);

    }

    @Override
    public String encode(@NonNull CharSequence rawPassword) {
        String password = String.valueOf(rawPassword);
        return encode(password.getBytes());
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword, @NonNull Charset charset) {
        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(charset));
    }
}
