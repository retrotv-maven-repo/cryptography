package dev.retrotv.crypt.owe.crc;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.Encode;
import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.Encrypt;
import dev.retrotv.crypt.owe.Password;

import java.nio.charset.StandardCharsets;

/**
 * CRC-32 알고리즘으로 암호화 하기 위한 {@link Checksum}, {@link Password} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class CRC32 extends Encrypt implements Checksum, Password {

    @Override
    public String encode(byte[] data) {
        return Encode.binaryToHex(encrypt(Algorithm.CRC32, data));
    }

    @Override
    public String encode(CharSequence rawPassword) {
        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            throw new CryptFailException("비교할 password 혹은 encodedPassword 값이 null 입니다.");
        }

        String password = String.valueOf(rawPassword);
        return encodedPassword.equals(encode(password));
    }
}
