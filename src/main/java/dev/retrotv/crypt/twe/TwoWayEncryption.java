package dev.retrotv.crypt.twe;

import dev.retrotv.crypt.exception.CryptFailException;
import lombok.NonNull;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * 양방향 암호화 클래스 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface TwoWayEncryption {

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException 암호화가 실패한 경우 발생
     * @param data 암호화 할 데이터
     * @param key 암호화 시, 사용할 키
     * @param spec 초기화 벡터
     * @return 암호화 된 데이터
     */
    byte[] encrypt(@NonNull byte[] data, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException;

    /**
     * 암호화 된 데이터를 복호화 하고, 복호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException 복호화가 실패한 경우 발생
     * @param encryptedData 암호화 된 데이터
     * @param key 복호화 시, 사용할 키
     * @param spec 초기화 벡터
     * @return 복호화 된 데이터
     */
    byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException;
}
