package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.data.utils.toHexString
import dev.retrotv.enums.Algorithm.Hash.SHA512
import dev.retrotv.utils.digest

/**
 * SHA-512 알고리즘으로 암호화 하기 위한 [Hash] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class SHA512 : Hash() {
    override fun hash(data: ByteArray): String {
        return toHexString(digest(SHA512, data))
    }
}
