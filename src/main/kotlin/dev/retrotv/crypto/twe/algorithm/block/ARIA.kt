package dev.retrotv.crypto.twe.algorithm.block

import dev.retrotv.crypto.twe.algorithm.BlockCipherAlgorithm
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.engines.ARIAEngine

/**
 * ARIA 알고리즘 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class ARIA : BlockCipherAlgorithm() {

    init {
        this.engine = ARIAEngine()
        this.algorithm = Algorithm.Cipher.ARIA
    }
}