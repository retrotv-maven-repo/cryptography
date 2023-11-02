package dev.retrotv.utils;

import dev.retrotv.enums.HashAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static dev.retrotv.enums.HashAlgorithm.CRC32;

/**
 * {@link MessageDigest}를 사용하는 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.8
 */
public class MessageDigestEncodeUtil {
    private static final Logger log = LogManager.getLogger();

    private MessageDigestEncodeUtil() {
        throw new IllegalStateException("유틸리티 클래스 입니다.");
    }

    /**
     * 지정된 {@link HashAlgorithm} 유형으로 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @param algorithm 암호화 시, 사용할 알고리즘
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    public static byte[] encode(HashAlgorithm algorithm, byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("data는 null일 수 없습니다.");
        }

        if (CRC32 == algorithm) {
            return encodeCRC32(data);
        }

        try {
            String algorithmName = algorithm.label();
            log.debug("알고리즘: {}", algorithmName);
            
            MessageDigest md = MessageDigest.getInstance(algorithm.label());
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { return new byte[0]; }
    }

    private static byte[] encodeCRC32(byte[] data) {
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(data);

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(crc32.getValue());

        return buffer.array();
    }
}
