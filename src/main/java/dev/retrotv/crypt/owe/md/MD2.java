package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.owe.MessageDigestEncrypt;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.EncodeUtil;
import lombok.NonNull;

import java.nio.charset.Charset;

/**
 * MD2 알고리즘으로 암호화 하기 위한 {@link MessageDigestEncrypt} 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class MD2 extends MessageDigestEncrypt {

    @Override
    public String encode(@NonNull byte[] data) {
        return EncodeUtil.binaryToHex(encode(Algorithm.MD2, data));
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword) {
        String password = String.valueOf(rawPassword);
        return encode(password.getBytes());
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword, @NonNull Charset charset) {
        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(charset));
    }
}
