package dev.retrotv.crypt;

import dev.retrotv.crypt.exception.CryptFailException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

public interface TwoWayEncryption {

    default String encrypt(String text, String key) {
        Optional.ofNullable(text).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        Optional.ofNullable(key).orElseThrow(() ->
                new CryptFailException("암호화 시, 사용할 키가 존재하지 않습니다."));

        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return new String(Base64.getEncoder().encode(encrypt(data, key)));
    }

    byte[] encrypt(byte[] data, String key);

    default String decrypt(String encryptedText, String key) {
        Optional.ofNullable(encryptedText).orElseThrow(() ->
                new CryptFailException("복호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        Optional.ofNullable(key).orElseThrow(() ->
                new CryptFailException("복호화 시, 사용할 키가 존재하지 않습니다."));

        byte[] data = Base64.getDecoder().decode(encryptedText.getBytes(StandardCharsets.UTF_8));
        return new String(decrypt(data, key));
    }

    byte[] decrypt(byte[] encryptedData, String key);

    String generateKey();
}
