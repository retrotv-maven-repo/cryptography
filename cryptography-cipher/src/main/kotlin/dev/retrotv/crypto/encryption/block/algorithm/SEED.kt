package dev.retrotv.crypto.encryption.block.algorithm

import dev.retrotv.crypto.encryption.block.BlockCipher
import dev.retrotv.crypto.enums.ECipher.SEED
import org.bouncycastle.crypto.engines.SEEDEngine

/**
 * SEED 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
class SEED : BlockCipher() {
    init {
        this.engine = SEEDEngine()
        this.algorithm = SEED
    }
}