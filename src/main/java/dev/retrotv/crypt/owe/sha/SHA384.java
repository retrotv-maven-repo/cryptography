package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.owe.MessageDigestEncrypt;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.EncodeUtil;

/**
 * SHA-384 알고리즘으로 암호화 하기 위한 {@link MessageDigestEncrypt} 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SHA384 extends MessageDigestEncrypt {

    @Override
    public String encode(byte[] data) {
        if (data == null) {
            logger.error(COMMON_MESSAGE.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(COMMON_MESSAGE.getMessage("exception.nullPointer", "data"));
        }

        return EncodeUtil.binaryToHex(encode(Algorithm.SHA384, data));
    }
}
