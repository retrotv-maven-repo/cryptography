package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.enums.Algorithm.Hash.SHA1

/**
 * SHA-1 알고리즘으로 암호화 하기 위한 [Hash] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class SHA1 : Hash() {

    init {
        this.algorithm = SHA1
    }

    override fun upgradeEncoding(encodedPassword: String?): Boolean {
        log.debug("파일 해싱 이외의 용도로 사용중일 경우, 알고리즘 업그레이드를 권장합니다.")
        return true
    }
}
