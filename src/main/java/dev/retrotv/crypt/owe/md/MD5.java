package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.owe.Encode;

import java.util.Optional;

/**
 * MD5 알고리즘으로 암호화 하기 위 {@link OneWayEncryption} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class MD5 extends Encode implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        Optional.ofNullable(data).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        return encode(Algorithm.MD5, data);
    }
}
