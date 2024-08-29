package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher.LEA
import org.bouncycastle.crypto.engines.LEAEngine

/**
 * LEA 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
class LEA : BlockCipher() {
    init {
        this.engine = LEAEngine()
        this.algorithm = LEA
    }
}