package dev.retrotv.crypto.util;

import dev.retrotv.data.utils.ByteUtils;
import dev.retrotv.data.utils.StringUtils;

import java.util.Objects;

/**
 * Base64 인코딩 및 디코딩 유틸리티 클래스
 *
 * @author yjj8353
 * @since 1.0.0
 */
public class Base64CodecUtils {
    private Base64CodecUtils() {
        throw new UnsupportedOperationException("Base64CodecUtils 클래스는 인스턴스화할 수 없습니다.");
    }

    /**
     * 바이트 배열을 Base64 문자열로 인코딩합니다.
     *
     * @param bytes 인코딩할 바이트 배열
     * @return Base64 문자열
     */
    public static String encode(byte[] bytes) {
        Objects.requireNonNull(bytes, "인코딩할 바이트 배열은 null일 수 없습니다.");
        return ByteUtils.toBase64String(bytes);
    }

    /**
     * Base64 문자열을 바이트 배열로 디코딩합니다.
     *
     * @param base64String 디코딩할 Base64 문자열
     * @return 바이트 배열
     */
    public static byte[] decode(String base64String) {
        Objects.requireNonNull(base64String, "디코딩할 문자열은 null일 수 없습니다.");
        return StringUtils.base64ToByteArray(base64String);
    }
}
