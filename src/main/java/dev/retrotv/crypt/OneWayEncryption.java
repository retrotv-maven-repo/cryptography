package dev.retrotv.crypt;

import dev.retrotv.crypt.exception.CryptFailException;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

public interface OneWayEncryption {

    default String encrypt(String text) {
        return encrypt(text, Encode.HEX);
    }

    default String encrypt(String text, Encode encode) {
        Optional.ofNullable(text).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        byte[] data = encrypt(text.getBytes(StandardCharsets.UTF_8));

        switch (encode) {
            case BASE64:
                return new String(Base64.getEncoder().encode(encrypt(data))).toLowerCase();

            case HEX:
            default:
                return DatatypeConverter.printHexBinary(data).toLowerCase();
        }
    }

    byte[] encrypt(byte[] data);

    default String encrypt(String text, String salt) {
        return encrypt(text.concat(salt));
    }

    default String encrypt(String text, String salt, Encode encode) {
        return encrypt(text.concat(salt), encode);
    }

    default boolean matches(String text, String encryptedText) {
        return encryptedText.equals(encrypt(text));
    }

    default boolean matches(String text, Encode encode, String encryptedText) {
        return encryptedText.equals(encrypt(text, encode));
    }

    default boolean matches(String text, String salt, String encryptedText) {
        return matches(text.concat(salt), encryptedText);
    }

    default boolean matches(String text, String salt, Encode encode, String encryptedText) {
        return matches(text.concat(salt), encode, encryptedText);
    }
}
