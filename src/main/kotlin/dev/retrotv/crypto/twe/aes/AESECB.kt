package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.exception.WrongKeyLengthException
import dev.retrotv.enums.CipherAlgorithm

/**
 * AES/ECB 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
class AESECB(keyLen: Int) : AES() {
    init {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw WrongKeyLengthException()
        }
        this.keyLen = keyLen
        algorithm = CipherAlgorithm.AESECB
    }
}
