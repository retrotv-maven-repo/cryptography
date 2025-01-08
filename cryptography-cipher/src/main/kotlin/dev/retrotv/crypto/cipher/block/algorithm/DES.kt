package dev.retrotv.crypto.cipher.block.algorithm

import dev.retrotv.crypto.cipher.block.BlockCipher
import dev.retrotv.crypto.enums.ECipher.DES
import org.bouncycastle.crypto.engines.DESEngine

/**
 * DES 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 * @deprecated 해킹에 취약한 양방향 암호화 알고리즘 입니다. 더 높은 보안성을 지닌 알고리즘 사용을 권장합니다.
 */
@SuppressWarnings("kotlin:S1133")
@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다. 더 높은 보안성을 지닌 알고리즘 사용을 권장합니다.")
class DES : BlockCipher() {
    init {
        this.engine = DESEngine()
        this.algorithm = DES
    }
}