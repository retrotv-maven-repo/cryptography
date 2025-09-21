package dev.retrotv.crypto.cipher.block.algorithm

import dev.retrotv.crypto.cipher.block.BlockCipher
import org.bouncycastle.crypto.engines.LEAEngine

import dev.retrotv.crypto.cipher.enums.ECipher.LEA

/**
 * LEA 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
class LEA : BlockCipher() {
    init {
        this.engine = LEAEngine()
        this.algorithm = LEA
    }
}