package dev.retrotv.crypt.twe;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.utils.CommonMessageUtil;
import lombok.NonNull;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 양방향 암호화 클래스 구현을 위한 인터페이스 입니다.
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
    default String encrypt(@NonNull String text,@NonNull byte[] key) throws CryptFailException {
        byte[] data = text.getBytes();
        return new String(Base64.getEncoder().encode(encrypt(data, key)));
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
    byte[] encrypt(byte[] data, byte[] key) throws CryptFailException;

    /**
     * 암호화 된 문자열을 복호화 하고, 복호화 된 문자열을 반환 합니다.
     * 복호화 할 문자열은 {@link Base64} 유형으로 인코딩 된 문자열이어야 합니다.
     *
     * @throws CryptFailException encryptedText 혹은 key가 null인 경우 발생
     * @param encryptedText 암호화 된 문자열
     * @param key 복호화 시, 사용할 키
     * @return 복호화 된 문자열
     */
    default String decrypt(@NonNull String encryptedText, @NonNull byte[] key) throws CryptFailException {
        byte[] data = Base64.getDecoder().decode(encryptedText.getBytes());
        return new String(decrypt(data, key));
    }

    /**
     * 암호화 된 데이터를 복호화 하고, 복호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException encryptedData 혹은 key가 null인 경우 발생
     * @param encryptedData 암호화 된 데이터
     * @param key 복호화 시, 사용할 키
     * @return 복호화 된 데이터
     */
    byte[] decrypt(byte[] encryptedData, byte[] key) throws CryptFailException;
}
