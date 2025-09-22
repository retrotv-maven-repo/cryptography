package dev.retrotv.crypto.cipher.result;

/**
 * 암호화 결과를 담는 클래스 입니다.
 */
public class Result {
    protected final byte[] data;

    public Result(byte[] data) {
        this.data = data;
    }

    public byte[] getData() {
        return data;
    }
}
