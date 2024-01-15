package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.enums.Algorithm.Hash.SHA512224

/**
 * SHA-512/224 알고리즘으로 암호화 하기 위한 [Hash] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class SHA512224 : Hash() {

    init {
        this.algorithm = SHA512224
    }
}
