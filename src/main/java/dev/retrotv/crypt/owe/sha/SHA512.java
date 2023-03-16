package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.Encrypt;
import dev.retrotv.crypt.owe.Password;

/**
 * SHA-512 알고리즘으로 암호화 하기 위한 {@link Checksum}, {@link Password} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SHA512 extends Encrypt implements Checksum, Password {

    @Override
    public String encode(byte[] data) {
        return null;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return null;
    }
}
