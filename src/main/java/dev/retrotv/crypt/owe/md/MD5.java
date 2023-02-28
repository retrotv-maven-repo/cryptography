package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.owe.Encode;

/**
 * MD5 알고리즘으로 암호화 하기 위 {@link OneWayEncryption} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class MD5 extends Encode implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        return encode(Algorithm.MD5, data);
    }
}
