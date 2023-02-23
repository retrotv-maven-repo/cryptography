package dev.retrotv.crypt;

import dev.retrotv.crypt.exception.CryptFailException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

public interface TwoWayEncryption {

    /**
     * 문자열을 암호화 하고, 암호화 된 문자열을 반환 받습니다.
     * 이 때, 암호화 된 데이터는 {@link Base64} 타입의 문자열로 인코딩 됩니다.
     *
     * @param text 암호화 할 문자열
     * @param key 암호화 시, 사용할 키
     * @return 암호화 된 문자열
     */
    default String encrypt(String text, String key) {
        Optional.ofNullable(text).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        Optional.ofNullable(key).orElseThrow(() ->
                new CryptFailException("암호화 시, 사용할 키가 존재하지 않습니다."));

        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return new String(Base64.getEncoder().encode(encrypt(data, key)));
    }

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 받습니다.
     *
     * @param data 암호화 할 데이터
     * @param key 암호화 시, 사용할 키
     * @return 암호화 된 데이터
     */
    byte[] encrypt(byte[] data, String key);

    /**
     * 암호화 된 문자열을 복호화 하고, 복호화 된 문자열을 반환 받습니다.
     * 복호화 할 문자열은 {@link Base64} 유형으로 인코딩 된 문자열이어야 합니다.
     *
     * @param encryptedText 암호화 된 문자열
     * @param key 복호화 시, 사용할 키
     * @return 복호화 된 문자열
     */
    default String decrypt(String encryptedText, String key) {
        Optional.ofNullable(encryptedText).orElseThrow(() ->
                new CryptFailException("복호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        Optional.ofNullable(key).orElseThrow(() ->
                new CryptFailException("복호화 시, 사용할 키가 존재하지 않습니다."));

        byte[] data = Base64.getDecoder().decode(encryptedText.getBytes(StandardCharsets.UTF_8));
        return new String(decrypt(data, key));
    }

    /**
     * 암호화 된 데이터를 복호화 하고, 복호화 된 데이터를 반환 받습니다.
     *
     * @param encryptedData 암호화 된 데이터
     * @param key 복호화 시, 사용할 키
     * @return 복호화 된 데이터
     */
    byte[] decrypt(byte[] encryptedData, String key);

    /**
     * 암복호화 시, 사용할 키를 생성합니다.
     *
     * @return 생성된 키
     */
    String generateKey();
}
