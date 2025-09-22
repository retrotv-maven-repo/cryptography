package dev.retrotv.crypto.cipher.block.algorithm;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;

import static dev.retrotv.crypto.cipher.enums.ECipher.AES;

/**
 * AES 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
public class AES extends BlockCipher {
    public AES() {
        this.engine = AESEngine.newInstance();
        this.algorithm = AES;
    }
}
