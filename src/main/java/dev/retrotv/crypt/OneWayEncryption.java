package dev.retrotv.crypt;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public interface OneWayEncryption {

    /**
     * 문자열 데이터를 암호화 하고, 암호화 된 문자열을 반환 받습니다.
     * 이 때, 암호화 된 데이터는 지정한 {@link Encode} 타입의 문자열로 인코딩 됩니다.
     * @param text 암호화 할 문자열
     * @param encode byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link Encode} 유형
     * @return 암호화 된 문자열
     */
    default String encrypt(String text, Encode encode) {
        byte[] data = encrypt(text.getBytes(StandardCharsets.UTF_8));

        switch (encode) {
            case HEX:
                return DatatypeConverter.printHexBinary(data).toLowerCase();
            case BASE64:
                return new String(Base64.getEncoder().encode(encrypt(data))).toLowerCase();
        }

        return null;
    }

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 받습니다.
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    byte[] encrypt(byte[] data);

    /**
     * 추가 문자열이 첨가 된 문자열 데이터를 암호화 하고, 암호화 된 문자열을 반환 받습니다.
     * 이 때, 암호화 된 데이터는 지정한 {@link Encode} 타입의 문자열로 인코딩 됩니다.
     * @param text 암호화 할 문자열
     * @param salt 암호화 할 문자열에 첨가할 추가 문자열
     * @param encode byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link Encode} 유형
     * @return 암호화 된 문자열
     */
    default String encrypt(String text, String salt, Encode encode) {
        return encrypt(text.concat(salt), encode);
    }

    /**
     * 암호화 되지 않은 문자열을 암호화 하고, 기존에 암호화 된 문자열과 비교하열 일치 여부를 반환합니다.
     * @param text 암호화 할 문자열
     * @param encode byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link Encode} 유형
     * @param encryptedText 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    default boolean matches(String text, Encode encode, String encryptedText) {
        return encryptedText.equals(encrypt(text, encode));
    }

    /**
     * 추가 문자열을 추가한 암호화 되지 않은 문자열을 암호화 하고, 기존에 암호화 된 문자열과 비교하여 일치 여부를 반환합니다.
     * @param text 암호화 할 문자열
     * @param salt 암호화 할 문자열에 첨가할 추가 문자열
     * @param encode byte[] 데이터를 문자열로 인코딩 할 때 사용할 {@link Encode} 유형
     * @param encryptedText 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    default boolean matches(String text, String salt, Encode encode, String encryptedText) {
        return matches(text.concat(salt), encode, encryptedText);
    }
}
