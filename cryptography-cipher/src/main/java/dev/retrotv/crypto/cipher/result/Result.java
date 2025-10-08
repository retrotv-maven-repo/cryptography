package dev.retrotv.crypto.cipher.result;

import lombok.Getter;

/**
 * 암호화 결과를 담는 클래스 입니다.
 */
@Getter
public class Result {
    protected final byte[] data;

    /**
     * Result 객체 생성자
     *
     * @param data 암호화 또는 복호화된 데이터
     */
    public Result(byte[] data) {
        this.data = data;
    }
}
