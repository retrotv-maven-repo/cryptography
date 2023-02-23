package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.exception.CryptFailException;

import java.util.Optional;

/**
 * SHA-384 알고리즘으로 암호화 하기 위한 {@link OneWayEncryption} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SHA384 extends SHA implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        Optional.ofNullable(data).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        return encode(Algorithm.SHA384, data);
    }
}
