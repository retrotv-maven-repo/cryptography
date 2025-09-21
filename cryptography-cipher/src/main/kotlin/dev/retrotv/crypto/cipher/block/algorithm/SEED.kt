package dev.retrotv.crypto.cipher.block.algorithm

import dev.retrotv.crypto.cipher.block.BlockCipher
import org.bouncycastle.crypto.engines.SEEDEngine

import dev.retrotv.crypto.cipher.enums.ECipher.SEED

/**
 * SEED 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
class SEED : BlockCipher() {
    init {
        this.engine = SEEDEngine()
        this.algorithm = SEED
    }
}