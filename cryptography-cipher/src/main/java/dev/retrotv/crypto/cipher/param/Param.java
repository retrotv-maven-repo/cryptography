package dev.retrotv.crypto.cipher.param;

import lombok.Getter;

/**
 * 암호화 및 복호화에 필요한 파라미터 클래스입니다.
 */
@Getter
public class Param {
    private final byte[] key;

    /**
     * Param 생성자
     *
     * @param key 암호화 및 복호화에 사용할 키
     */
    public Param(byte[] key) {
        this.key = key;
    }
}
