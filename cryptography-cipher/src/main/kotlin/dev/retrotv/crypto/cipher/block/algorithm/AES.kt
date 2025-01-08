package dev.retrotv.crypto.cipher.block.algorithm

import dev.retrotv.crypto.cipher.block.BlockCipher
import dev.retrotv.crypto.enums.ECipher.AES
import org.bouncycastle.crypto.engines.AESEngine

/**
 * AES 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
class AES : BlockCipher() {
    init {
        this.engine = AESEngine.newInstance()
        this.algorithm = AES
    }
}