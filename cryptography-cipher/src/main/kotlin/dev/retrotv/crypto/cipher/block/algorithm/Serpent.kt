package dev.retrotv.crypto.cipher.block.algorithm

import dev.retrotv.crypto.cipher.block.BlockCipher
import org.bouncycastle.crypto.engines.SerpentEngine

import dev.retrotv.crypto.cipher.enums.ECipher.SERPENT

/**
 * Serpent 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
class Serpent : BlockCipher() {
    init {
        this.engine = SerpentEngine()
        this.algorithm = SERPENT
    }
}