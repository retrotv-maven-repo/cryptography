package dev.retrotv.crypto.hash;

import dev.retrotv.data.enums.EncodeFormat;
import lombok.NonNull;

import java.util.Arrays;

/**
 * 바이너리 데이터를 해시하는 인터페이스입니다.
 */
public interface BinaryHash {

    /**
     * 바이너리 데이터를 해시한 값을 생성하고 반환합니다.
     *
     * @param data 해시 할 바이너리 데이터
     * @return 해시 값
     */
    byte[] hashing(@NonNull byte[] data);

    /**
     * 바이너리 데이터를 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     *
     * @param data 해시 할 바이너리 데이터
     * @param digest 비교 할 해시 값
     * @return 일치 여부
     */
    default boolean matches(@NonNull byte[] data, byte[] digest) {
        return Arrays.equals(digest, hashing(data));
    }

    /**
     * 바이너리 데이터를 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     * HEX 값으로 비교하며, 대소문자를 구분하지 않습니다.
     *
     * @param data 해시 할 바이너리 데이터
     * @param digest 비교할 해시 값
     * @return 일치 여부
     */
    default boolean matches(@NonNull byte[] data, String digest) {
        return matches(data, digest, EncodeFormat.HEX);
    }

    /**
     * 바이너리 데이터를 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     * 대소문자를 구분하지 않습니다.
     *
     * @param data 해시 할 바이너리 데이터
     * @param digest 비교할 해시 값
     * @param encoderFormat 해시 값을 인코딩할 포맷 (기본값: HEX)
     * @return 일치 여부
     */
    boolean matches(@NonNull byte[] data, String digest, EncodeFormat encoderFormat);
}
