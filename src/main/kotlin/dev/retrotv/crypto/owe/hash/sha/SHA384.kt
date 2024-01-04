package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.HashAlgorithm
import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.utils.toHexString
import dev.retrotv.enums.Algorithm.Hash.SHA384
import dev.retrotv.utils.digest
import dev.retrotv.utils.encode

/**
 * SHA-384 알고리즘으로 암호화 하기 위한 [HashAlgorithm] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class SHA384 : HashAlgorithm() {
    override fun hash(data: ByteArray): String {
        return toHexString(digest(SHA384, data))
    }

    override fun hash(data: ByteArray, encodeFormat: EncodeFormat): String {
        return encode(encodeFormat, digest(SHA384, data))
    }
}
