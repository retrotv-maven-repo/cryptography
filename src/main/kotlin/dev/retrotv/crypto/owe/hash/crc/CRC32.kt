package dev.retrotv.crypto.owe.hash.crc

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.enums.HashAlgorithm
import dev.retrotv.utils.EncodeUtil
import dev.retrotv.utils.MessageDigestEncodeUtil

/**
 * CRC-32 알고리즘으로 암호화 하기 위한 [Checksum], [PasswordWithSalt] 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
class CRC32 : Hash() {
    override fun hash(data: ByteArray): String {

        // 앞에 0이 패딩되는 부분을 무시하고 뒤의 8자리만 잘라낸다
        return EncodeUtil.binaryToHex(MessageDigestEncodeUtil.encode(HashAlgorithm.CRC32, data))
                         .substring(8)
    }
}
