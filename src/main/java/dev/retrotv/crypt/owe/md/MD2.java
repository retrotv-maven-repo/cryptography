package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.Encode;
import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.Encrypt;
import dev.retrotv.crypt.owe.PasswordWithSalt;

import java.nio.charset.StandardCharsets;

/**
 * MD2 알고리즘으로 암호화 하기 위 {@link Checksum}, {@link PasswordWithSalt} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class MD2 extends Encrypt implements Checksum, PasswordWithSalt {

    @Override
    public String encode(byte[] data) {
        return Encode.binaryToHex(encode(Algorithm.MD2, data));
    }

    @Override
    public String encode(CharSequence rawPassword) {
        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(StandardCharsets.UTF_8));
    }
}
