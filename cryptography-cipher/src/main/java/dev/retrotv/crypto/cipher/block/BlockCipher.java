package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.enums.ECipher;
import lombok.Getter;

/**
 * 블록 암호화 알고리즘 구현을 위한 추상 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.0.0
 */
@Getter
public abstract class BlockCipher {
    protected org.bouncycastle.crypto.BlockCipher engine;
    protected ECipher algorithm;
}
