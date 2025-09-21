package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.TwoWayEncryption;
import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.cipher.enums.EMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 암호화 모드 구현을 위한 추상 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.0.0
 */
public abstract class CipherMode implements TwoWayEncryption {
    protected final Logger log = LoggerFactory.getLogger(getClass());
    protected final EMode mode;
    protected final ECipher algorithm;
    protected org.bouncycastle.crypto.BlockCipher engine;

    /**
     * @param mode 암호화 모드
     * @param blockCipher 블록 암호화 클래스
     */
    public CipherMode(EMode mode, BlockCipher blockCipher) {
        this.mode = mode;
        this.algorithm = blockCipher.getAlgorithm();
        this.engine = blockCipher.getEngine();
    }

    public EMode getMode() {
        return mode;
    }

    public ECipher getAlgorithm() {
        return algorithm;
    }

    public org.bouncycastle.crypto.BlockCipher getEngine() {
        return engine;
    }
}
