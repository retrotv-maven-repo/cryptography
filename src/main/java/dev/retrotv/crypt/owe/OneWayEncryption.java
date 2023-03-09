package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.Encode;
import dev.retrotv.crypt.EncodeFormat;
import dev.retrotv.crypt.exception.CryptFailException;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * 단방향 알고리즘 클래스 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface OneWayEncryption {

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException data가 null 일 경우 발생
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    byte[] encrypt(byte[] data);

    /**
     * 문자열 데이터를 암호화 하고, 암호화 된 문자열을 반환 합니다.
     * 이 때, 암호화 된 데이터는 지정한 {@link EncodeFormat} 타입의 문자열로 인코딩 됩니다. (null일 경우 HEX 타입으로 강제 지정)
     *
     * @throws CryptFailException data가 null 일 경우 발생
     * @param data 암호화 할 문자열
     * @param encodeFormat byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link EncodeFormat} 유형
     * @return 암호화 된 문자열
     */
    default String encrypt(byte[] data, EncodeFormat encodeFormat) {
        Optional.ofNullable(data).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        return Encode.binaryEncode(encodeFormat, encrypt(data));
    }

    /**
     * 문자열 데이터를 암호화 하고, 암호화 된 문자열을 반환 합니다.
     * 이 때, 암호화 된 데이터는 {@link EncodeFormat}의 HEX 타입의 문자열로 인코딩 됩니다.
     *
     * @throws CryptFailException text가 null 일 경우 발생
     * @param text 암호화 할 문자열
     * @return 암호화 된 문자열
     */
    default String encrypt(String text) {
        return encrypt(text, EncodeFormat.HEX);
    }

    /**
     * 문자열 데이터를 암호화 하고, 암호화 된 문자열을 반환 합니다.
     * 이 때, 암호화 된 데이터는 지정한 {@link EncodeFormat} 타입의 문자열로 인코딩 됩니다. (null일 경우 HEX 타입으로 강제 지정)
     *
     * @throws CryptFailException text가 null 일 경우 발생
     * @param text 암호화 할 문자열
     * @param encodeFormat byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link EncodeFormat} 유형
     * @return 암호화 된 문자열
     */
    default String encrypt(String text, EncodeFormat encodeFormat) {
        Optional.ofNullable(text).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        byte[] data = encrypt(text.getBytes(StandardCharsets.UTF_8));

        return Encode.binaryEncode(encodeFormat, data);
    }

    /**
     * 추가 문자열이 첨가 된 문자열 데이터를 암호화 하고, 암호화 된 문자열을 반환 합니다.
     * 이 때, 암호화 된 데이터는 {@link EncodeFormat}의 HEX 타입의 문자열로 인코딩 됩니다.
     *
     * @throws CryptFailException text가 null 일 경우 발생
     * @param text 암호화 할 문자열
     * @param salt 암호화 할 문자열에 첨가할 추가 문자열
     * @return 암호화 된 문자열
     */
    default String encrypt(String text, String salt) {
        return encrypt(text.concat(salt));
    }

    /**
     * 추가 문자열이 첨가 된 문자열 데이터를 암호화 하고, 암호화 된 문자열을 반환 합니다.
     * 이 때, 암호화 된 데이터는 지정한 {@link EncodeFormat} 타입의 문자열로 인코딩 됩니다. (null일 경우 HEX 타입으로 강제 지정)
     *
     * @throws CryptFailException text가 null 일 경우 발생
     * @param text 암호화 할 문자열
     * @param salt 암호화 할 문자열에 첨가할 추가 문자열
     * @param encodeFormat byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link EncodeFormat} 유형
     * @return 암호화 된 문자열
     */
    default String encrypt(String text, String salt, EncodeFormat encodeFormat) {
        return encrypt(text.concat(salt), encodeFormat);
    }

    /**
     * 암호화 되지 않은 문자열을 암호화 하고, 기존에 암호화 된 문자열과 비교하열 일치 여부를 반환 합니다.
     * 이 때, 암호화 되지 않은 문자열은 {@link EncodeFormat}의 HEX 타입의 문자열로 인코딩 되고 비교합니다.
     *
     * @throws CryptFailException text가 null 일 경우 발생
     * @param text 암호화 할 문자열
     * @param encryptedText 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    default boolean matches(String text, String encryptedText) {
        return encryptedText.equals(encrypt(text));
    }

    /**
     * 암호화 되지 않은 문자열을 암호화 하고, 기존에 암호화 된 문자열과 비교하열 일치 여부를 반환 합니다.
     * 이 때, 암호화 되지 않은 문자열은 지정된 {@link EncodeFormat} 타입의 문자열로 인코딩 된 뒤 비교합니다. (null일 경우 HEX 타입으로 강제 지정)
     *
     * @throws CryptFailException text가 null 일 경우 발생
     * @param text 암호화 할 문자열
     * @param encodeFormat byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link EncodeFormat} 유형
     * @param encryptedText 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    default boolean matches(String text, EncodeFormat encodeFormat, String encryptedText) {
        return encrypt(text, encodeFormat).equals(encryptedText);
    }

    /**
     * 추가 문자열을 첨가한 암호화 되지 않은 문자열을 암호화 하고, 기존에 암호화 된 문자열과 비교하여 일치 여부를 반환 합니다.
     * 이 때, 암호화 되지 않은 문자열은 {@link EncodeFormat}의 HEX 타입의 문자열로 인코딩 된 뒤 비교합니다.
     *
     * @throws CryptFailException text가 null 일 경우 발생
     * @param text 암호화 할 문자열
     * @param salt 암호화 할 문자열에 첨가할 추가 문자열
     * @param encryptedText 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    default boolean matches(String text, String salt, String encryptedText) {
        return matches(text.concat(salt), encryptedText);
    }

    /**
     * 추가 문자열을 첨가한 암호화 되지 않은 문자열을 암호화 하고, 기존에 암호화 된 문자열과 비교하여 일치 여부를 반환 합니다.
     * 이 때, 암호화 되지 않은 문자열은 지정된 {@link EncodeFormat} 타입의 문자열로 인코딩 된 뒤 비교합니다. (null일 경우 HEX 타입으로 강제 지정)
     *
     * @throws CryptFailException text가 null 일 경우 발생
     * @param text 암호화 할 문자열
     * @param salt 암호화 할 문자열에 첨가할 추가 문자열
     * @param encodeFormat byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link EncodeFormat} 유형
     * @param encryptedText 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    default boolean matches(String text, String salt, EncodeFormat encodeFormat, String encryptedText) {
        return matches(text.concat(salt), encodeFormat, encryptedText);
    }
}
