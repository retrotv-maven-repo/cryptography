package dev.retrotv.crypto.cipher.param;

/**
 * 암호화 및 복호화에 필요한 파라미터 클래스 입니다.
 * Param 클래스를 상속받습니다.
 */
public class ParamWithIV extends Param {
    protected final byte[] iv;

    public ParamWithIV(byte[] key, byte[] iv) {
        super(key);
        this.iv = iv;
    }

    public byte[] getIv() {
        return iv;
    }
}
