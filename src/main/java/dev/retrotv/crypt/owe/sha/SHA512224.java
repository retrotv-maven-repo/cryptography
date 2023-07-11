package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.owe.MessageDigestEncode;
import dev.retrotv.utils.EncodeUtil;
import lombok.NonNull;

import static dev.retrotv.enums.HashAlgorithm.SHA512224;

/**
 * SHA-512/224 알고리즘으로 암호화 하기 위한 {@link MessageDigestEncode} 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SHA512224 extends MessageDigestEncode {
    
    @Override
    public String hash(@NonNull byte[] data) {
        return EncodeUtil.binaryToHex(encode(SHA512224, data));
    }
}
