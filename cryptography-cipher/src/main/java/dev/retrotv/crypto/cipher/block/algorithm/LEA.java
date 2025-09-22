package dev.retrotv.crypto.cipher.block.algorithm;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import org.bouncycastle.crypto.engines.LEAEngine;

import static dev.retrotv.crypto.cipher.enums.ECipher.LEA;

/**
 * LEA 암호화 알고리즘을 사용하는 블록 암호화 클래스 입니다.
 */
public class LEA extends BlockCipher {
    public LEA() {
        this.engine = new LEAEngine();
        this.algorithm = LEA;
    }
}
