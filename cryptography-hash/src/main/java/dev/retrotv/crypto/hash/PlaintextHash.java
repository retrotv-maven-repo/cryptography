package dev.retrotv.crypto.hash;

import dev.retrotv.data.enums.EncodeFormat;
import lombok.NonNull;

import java.nio.charset.Charset;

/**
 * 평문을 해시하는 인터페이스입니다.
 */
public interface PlaintextHash extends BinaryHash {

    /**
     * 평문을 해시한 값을 생성하고 반환합니다.
     *
     * @param plaintext 해시 할 평문
     * @return 해시 값
     */
    default byte[] hashing(@NonNull CharSequence plaintext) {
        return hashing(plaintext.toString().getBytes());
    }

    /**
     * 평문을 해시한 값을 생성하고 반환합니다.
     * 캐릭터 셋을 지정할 경우, 해당 캐릭터 셋으로 인코딩하여 해시합니다.
     *
     * @param plaintext 해시 할 평문
     * @param charset 해시 할 평문의 캐릭터 셋
     * @return 해시 값
     */
    default byte[] hashing(@NonNull CharSequence plaintext, Charset charset) {
        return hashing(plaintext.toString().getBytes(charset));
    }

    /**
     * 평문을 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     * HEX 값으로 비교하며, 대소문자를 구분하지 않습니다.
     *
     * @param plaintext 해시 할 평문
     * @param digest 비교할 해시 값
     * @return 일치 여부
     */
    default boolean matches(@NonNull CharSequence plaintext, String digest) {
        return matches(plaintext.toString().getBytes(), digest, EncodeFormat.HEX);
    }

    /**
     * 평문을 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     * 대소문자를 구분하지 않습니다.
     *
     * @param plaintext 해시 할 평문
     * @param digest 비교할 해시 값
     * @param encoderFormat 해시 값을 인코딩할 포맷 (기본값: HEX)
     * @return 일치 여부
     */
    default boolean matches(@NonNull CharSequence plaintext, String digest, EncodeFormat encoderFormat) {
        return matches(plaintext.toString().getBytes(), digest, encoderFormat);
    }
}
