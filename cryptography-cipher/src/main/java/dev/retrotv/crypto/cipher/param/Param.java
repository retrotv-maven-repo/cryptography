package dev.retrotv.crypto.cipher.param;

/**
 * 암호화 및 복호화에 필요한 파라미터 클래스입니다.
 */
public class Param {
    private final byte[] key;

    public Param(byte[] key) {
        this.key = key;
    }

    public byte[] getKey() {
        return key;
    }
}
