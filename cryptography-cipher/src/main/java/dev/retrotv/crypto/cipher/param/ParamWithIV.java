package dev.retrotv.crypto.cipher.param;

import lombok.Getter;

/**
 * 암호화 및 복호화에 필요한 파라미터 클래스 입니다.
 * Param 클래스를 상속받습니다.
 */
@Getter
public class ParamWithIV extends Param {
    protected final byte[] iv;

    /**
     * ParamWithIV 생성자
     *
     * @param key 암호화 및 복호화에 사용할 키
     * @param iv 초기화 벡터(IV)
     */
    public ParamWithIV(byte[] key, byte[] iv) {
        super(key);
        this.iv = iv;
    }
}
