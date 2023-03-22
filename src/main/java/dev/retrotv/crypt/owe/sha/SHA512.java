package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.Encode;
import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.Encrypt;
import dev.retrotv.crypt.owe.PasswordWithSalt;

import java.nio.charset.StandardCharsets;

/**
 * SHA-512 알고리즘으로 암호화 하기 위한 {@link Checksum}, {@link PasswordWithSalt} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SHA512 extends Encrypt implements Checksum, PasswordWithSalt {

    @Override
    public String encode(byte[] data) {
        return Encode.binaryToHex(encrypt(Algorithm.SHA512, data));
    }

    @Override
    public String encode(CharSequence rawPassword) {
        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(StandardCharsets.UTF_8));
    }
}
