package dev.retrotv.crypto.encryption.block.algorithm

import dev.retrotv.crypto.encryption.block.BlockCipher
import dev.retrotv.crypto.enums.ECipher.SERPENT
import org.bouncycastle.crypto.engines.SerpentEngine

/**
 * Serpent 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
class Serpent : BlockCipher() {
    init {
        this.engine = SerpentEngine()
        this.algorithm = SERPENT
    }
}