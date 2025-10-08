package dev.retrotv.crypto.cipher.result;

import lombok.Getter;

/**
 * AEAD 암호화 결과를 담는 클래스 입니다.
 */
@Getter
public class AEADResult extends Result {
    private final byte[] tag;

    /**
     * AEADResult 객체 생성자
     *
     * @param data 암호화 또는 복호화된 데이터
     * @param tag 인증 태그
     */
    public AEADResult(byte[] data, byte[] tag) {
        super(data);
        this.tag = tag;
    }
}
