package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.TwoWayEncryption;
import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.cipher.enums.EMode;
import lombok.Getter;

/**
 * 암호화 모드 구현을 위한 추상 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.0.0
 */
@Getter
public abstract class BlockCipherMode implements TwoWayEncryption {
    protected final EMode mode;
    protected final ECipher algorithm;
    protected org.bouncycastle.crypto.BlockCipher engine;

    /**
     * @param mode 암호화 모드
     * @param blockCipher 블록 암호화 클래스
     */
    protected BlockCipherMode(EMode mode, BlockCipher blockCipher) {
        this.mode = mode;
        this.algorithm = blockCipher.getAlgorithm();
        this.engine = blockCipher.getEngine();
    }
}
