package dev.retrotv.crypto.twe;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.enums.EncodeFormat;
import dev.retrotv.utils.EncodeUtil;

import org.apache.commons.codec.DecoderException;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static dev.retrotv.enums.EncodeFormat.*;

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
     * @param data 암호화 할 데이터
     * @param key 암호화 시, 사용할 키
     * @param spec 초기화 벡터
     * @return 암호화 된 데이터
     */
    byte[] encrypt(byte[] data, Key key, AlgorithmParameterSpec spec);

    /**
     * 데이터를 암호화 하고, 지정된 인코딩 포맷으로 인코딩 후 반환합니다.
     *
     * @param data 암호화 할 데이터
     * @param key 암호화 시, 사용할 키
     * @param spec 초기화 벡터
     * @param format 인코딩 포맷
     * @return 암호화 완료 후, 지정된 포맷으로 인코딩 된 데이터
     */
    default String encrypt(byte[] data, Key key, AlgorithmParameterSpec spec, EncodeFormat format) {
        byte[] encryptedData = encrypt(data, key, spec);

        if (format == HEX) {
            return EncodeUtil.binaryToHex(encryptedData);
        } else {
            return EncodeUtil.binaryToBase64(encryptedData);
        }
    }

    /**
     * 암호화 된 데이터를 복호화 하고, 복호화 된 데이터를 반환 합니다.
     *
     * @param encryptedData 암호화 된 데이터
     * @param key 복호화 시, 사용할 키
     * @param spec 초기화 벡터
     * @return 복호화 된 데이터
     */
    byte[] decrypt(byte[] encryptedData, Key key, AlgorithmParameterSpec spec);

    /**
     * 암호화 된 데이터를 지정된 인코딩 포맷으로 디코딩 후, 복호화 된 데이터를 반환 합니다.
     *
     * @param encryptedData 인코딩 된 암호화 데이터
     * @param key 암호화 시, 사용할 키
     * @param spec 초기화 벡터
     * @param format 인코딩 포맷
     * @return 복호화 된 데이터
     */
    default byte[] decrypt(String encryptedData, Key key, AlgorithmParameterSpec spec, EncodeFormat format) {
        byte[] decodedData;

        if (format == HEX) {
            try {
                decodedData = EncodeUtil.hexToBinary(encryptedData);
            } catch (DecoderException e) {
                throw new CryptoFailException("바이너리로 변환하는 과정에서 오류가 발생했습니다. Hex 값으로 인코딩된 값이 맞는지 확인하십시오.", e);
            }
        } else {
            decodedData = EncodeUtil.base64ToBinary(encryptedData);
        }

        return decrypt(decodedData, key, spec);
    }
}
