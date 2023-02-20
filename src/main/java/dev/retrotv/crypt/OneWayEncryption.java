package dev.retrotv.crypt;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public interface OneWayEncryption {

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

    byte[] encrypt(byte[] data);

    default String encrypt(String text, String salt, Encode encode) {
        return encrypt(text.concat(salt), encode);
    }

    default boolean matches(String text, Encode encode, String encryptedText) {
        return encryptedText.equals(encrypt(text, encode));
    }

    default boolean matches(String text, String salt, Encode encode, String encryptedText) {
        return matches(text.concat(salt), encode, encryptedText);
    }
}
