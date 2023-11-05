package dev.retrotv.crypto.owe.hash.md

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.enums.HashAlgorithm
import dev.retrotv.utils.EncodeUtil
import dev.retrotv.utils.MessageDigestEncodeUtil

/**
 * MD5 알고리즘으로 암호화 하기 위한 [MessageDigestEncodeUtil] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
class MD5 : Hash() {
    override fun hash(data: ByteArray): String {
        return EncodeUtil.binaryToHex(MessageDigestEncodeUtil.encode(HashAlgorithm.MD5, data))
    }
}
