package dev.retrotv.crypto.cipher.block.algorithm;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import org.bouncycastle.crypto.engines.DESEngine;

import static dev.retrotv.crypto.cipher.enums.ECipher.DES;

/**
 * DES 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 * @deprecated 해킹에 취약한 양방향 암호화 알고리즘 입니다. 더 높은 보안성을 지닌 알고리즘 사용을 권장합니다.
 */
@Deprecated
public class DES extends BlockCipher {
    public DES() {
        this.engine = new DESEngine();
        this.algorithm = DES;
    }
}
