package dev.retrotv.crypto.twe.aes

import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.getMessage

/**
 * AES/ECB 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class AESECB(keyLen: Int) : AES() {

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        algorithm = Algorithm.Cipher.AESECB
    }
}
