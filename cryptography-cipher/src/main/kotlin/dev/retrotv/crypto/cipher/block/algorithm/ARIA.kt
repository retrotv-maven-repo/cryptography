package dev.retrotv.crypto.cipher.block.algorithm

import dev.retrotv.crypto.cipher.block.BlockCipher
import org.bouncycastle.crypto.engines.ARIAEngine

import dev.retrotv.crypto.cipher.enums.ECipher.ARIA

/**
 * ARIA 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
class ARIA : BlockCipher() {
    init {
        this.engine = ARIAEngine()
        this.algorithm = ARIA
    }
}