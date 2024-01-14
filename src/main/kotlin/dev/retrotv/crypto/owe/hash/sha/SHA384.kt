package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.data.utils.toHexString
import dev.retrotv.enums.Algorithm.Hash.SHA384
import dev.retrotv.utils.digest

/**
 * SHA-384 알고리즘으로 암호화 하기 위한 [Hash] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class SHA384 : Hash() {
    override fun hash(data: ByteArray): String {
        return toHexString(digest(SHA384, data))
    }
}
