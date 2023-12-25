package dev.retrotv.crypto.twe.des

import dev.retrotv.enums.Algorithm

/**
 * TripleDES/ECB 양방향 암호화 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class TripleDESECB : TripleDES() {

    init {
        algorithm = Algorithm.Cipher.TRIPLE_DESECB
    }
}
