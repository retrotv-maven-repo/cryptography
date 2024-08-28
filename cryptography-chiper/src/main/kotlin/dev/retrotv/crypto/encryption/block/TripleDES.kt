package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher.TRIPLE_DES
import org.bouncycastle.crypto.engines.DESedeEngine

@SuppressWarnings("kotlin:S1133")
@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다.")
class TripleDES : BlockCipher() {
    init {
        this.engine = DESedeEngine()
        this.algorithm = TRIPLE_DES
    }
}