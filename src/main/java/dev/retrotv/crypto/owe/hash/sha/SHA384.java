package dev.retrotv.crypto.owe.hash.sha;

import dev.retrotv.crypto.owe.hash.Hash;
import dev.retrotv.utils.MessageDigestEncodeUtil;
import dev.retrotv.utils.EncodeUtil;

import static dev.retrotv.enums.HashAlgorithm.SHA384;

/**
 * SHA-384 알고리즘으로 암호화 하기 위한 {@link MessageDigestEncodeUtil} 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SHA384 extends Hash {

    @Override
    public String hash(byte[] data) {
        return EncodeUtil.binaryToHex(MessageDigestEncodeUtil.encode(SHA384, data));
    }
}
