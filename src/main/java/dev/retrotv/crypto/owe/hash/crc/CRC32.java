package dev.retrotv.crypto.owe.hash.crc;

import dev.retrotv.crypto.owe.hash.Checksum;
import dev.retrotv.crypto.owe.hash.Hash;
import dev.retrotv.crypto.owe.hash.PasswordWithSalt;
import dev.retrotv.utils.EncodeUtil;
import dev.retrotv.utils.MessageDigestEncodeUtil;

import static dev.retrotv.enums.HashAlgorithm.CRC32;

/**
 * CRC-32 알고리즘으로 암호화 하기 위한 {@link Checksum}, {@link PasswordWithSalt} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class CRC32 extends Hash {

    @Override
    public String hash(byte[] data) {

        // 앞에 0이 패딩되는 부분을 무시하고 뒤의 8자리만 잘라낸다
        return EncodeUtil.binaryToHex(MessageDigestEncodeUtil.encode(CRC32, data))
                         .substring(8);
    }
}
