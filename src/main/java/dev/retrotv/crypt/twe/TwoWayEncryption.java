package dev.retrotv.crypt.twe;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.random.SecurityStrength;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * 양방향 알고리즘 클래스 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface TwoWayEncryption {

    /**
     * 문자열을 암호화 하고, 암호화 된 문자열을 반환 합니다.
     * 이 때, 암호화 된 데이터는 {@link Base64} 타입의 문자열로 인코딩 됩니다.
     *
     * @throws CryptFailException text 혹은 key가 null인 경우 발생
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
        byte[] keyData = key.getBytes(StandardCharsets.UTF_8);

        return new String(Base64.getEncoder().encode(encrypt(data, keyData)));
    }

    /**
     * 문자열을 암호화 하고, 암호화 된 문자열을 반환 합니다.
     * 이 때, 암호화 된 데이터는 {@link Base64} 타입의 문자열로 인코딩 됩니다.
     *
     * @throws CryptFailException text 혹은 key가 null인 경우 발생
     * @param data 암호화 할 데이터
     * @param key 암호화 시, 사용할 키
     * @return 암호화 된 문자열
     */
    byte[] encrypt(byte[] data, byte[] key);

    /**
     * 암호화 된 문자열을 복호화 하고, 복호화 된 문자열을 반환 합니다.
     * 복호화 할 문자열은 {@link Base64} 유형으로 인코딩 된 문자열이어야 합니다.
     *
     * @throws CryptFailException encryptedText 혹은 key가 null인 경우 발생
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
        byte[] keyData = key.getBytes(StandardCharsets.UTF_8);

        return new String(decrypt(data, keyData));
    }

    /**
     * 암호화 된 데이터를 복호화 하고, 복호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException encryptedData 혹은 key가 null인 경우 발생
     * @param encryptedData 암호화 된 데이터
     * @param key 복호화 시, 사용할 키
     * @return 복호화 된 데이터
     */
    byte[] decrypt(byte[] encryptedData, byte[] key);

    /**
     * 암복호화 시, 사용할 키를 생성합니다.
     *
     * @param securityStrength 보안 강도: {@link SecurityStrength} 참조
     * @return 생성된 키
     */
    String generateKey(SecurityStrength securityStrength);
}
