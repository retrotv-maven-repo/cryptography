package dev.retrotv.crypto.util;

import dev.retrotv.crypto.exception.DecodeException;
import dev.retrotv.data.utils.ByteUtils;
import dev.retrotv.data.utils.StringUtils;
import org.apache.commons.codec.DecoderException;

import java.util.Objects;

/**
 * HEX 인코딩 및 디코딩 유틸리티 클래스.
 *
 * @author yjj8353
 * @since 1.0.0
 */
public class HEXCodecUtils {
    private HEXCodecUtils() {
        throw new UnsupportedOperationException("HEXCodeUtils 클래스는 인스턴스화할 수 없습니다.");
    }

    /**
     * 바이트 배열을 HEX 문자열로 인코딩합니다.
     *
     * @param bytes 인코딩할 바이트 배열
     * @return HEX 문자열
     */
    public static String encode(byte[] bytes) {
        Objects.requireNonNull(bytes, "인코딩할 바이트 배열은 null일 수 없습니다.");
        return ByteUtils.toHexString(bytes);
    }

    /**
     * HEX 문자열을 바이트 배열로 디코딩합니다.
     *
     * @param hexString 디코딩할 HEX 문자열
     * @return 바이트 배열
     * @throws DecodeException HEX 문자열을 디코딩하는 도중 오류가 발생한 경우
     */
    public static byte[] decode(String hexString) {
        Objects.requireNonNull(hexString, "디코딩할 문자열은 null일 수 없습니다.");
        byte[] bytes;
        try {
            bytes = StringUtils.hexToByteArray(hexString);
        } catch (DecoderException ex) {
            throw new DecodeException("HEX 문자열을 디코딩하는 도중 오류가 발생했습니다.", ex);
        }

        return bytes;
    }
}
