package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher.DES
import org.bouncycastle.crypto.engines.DESEngine

@SuppressWarnings("kotlin:S1133")
@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다.")
class DES : BlockCipher() {
    init {
        this.engine = DESEngine()
        this.algorithm = DES
    }
}