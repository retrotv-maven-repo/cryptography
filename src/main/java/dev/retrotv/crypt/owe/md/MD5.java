package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.owe.MessageDigestEncode;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.EncodeUtil;
import lombok.NonNull;

import java.nio.charset.Charset;

/**
 * MD5 알고리즘으로 암호화 하기 위한 {@link MessageDigestEncode} 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class MD5 extends MessageDigestEncode {
    @Override
    public String hash(@NonNull byte[] data) {
        return EncodeUtil.binaryToHex(encode(Algorithm.MD5, data));
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword) {
        String password = String.valueOf(rawPassword);
        return hash(password.getBytes());
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword, @NonNull Charset charset) {
        String password = String.valueOf(rawPassword);
        return hash(password.getBytes(charset));
    }
}
