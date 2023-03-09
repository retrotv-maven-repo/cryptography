package dev.retrotv.crypt.owe.crc;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.owe.OneWayEncryption;
import dev.retrotv.crypt.owe.Encrypt;

/**
 * CRC-32 알고리즘으로 암호화 하기 위한 {@link OneWayEncryption} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class CRC32 extends Encrypt implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        return encrypt(Algorithm.CRC32, data);
    }
}
