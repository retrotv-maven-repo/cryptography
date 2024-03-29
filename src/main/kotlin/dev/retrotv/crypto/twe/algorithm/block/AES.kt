package dev.retrotv.crypto.twe.algorithm.block

import dev.retrotv.crypto.twe.algorithm.BlockCipherAlgorithm
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.engines.AESEngine

/**
 * AES 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class AES : BlockCipherAlgorithm() {

    init {
        this.engine = AESEngine.newInstance()
        this.algorithm = Algorithm.Cipher.AES
    }
}
