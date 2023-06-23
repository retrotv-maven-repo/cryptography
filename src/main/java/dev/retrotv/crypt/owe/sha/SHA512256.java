package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.owe.MessageDigestEncrypt;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.EncodeUtil;
import lombok.NonNull;

/**
 * SHA-512/256 알고리즘으로 암호화 하기 위한 {@link MessageDigestEncrypt} 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SHA512256 extends MessageDigestEncrypt {

    @Override
    public String encode(@NonNull byte[] data) {
        return EncodeUtil.binaryToHex(encode(Algorithm.SHA512256, data));
    }
}
