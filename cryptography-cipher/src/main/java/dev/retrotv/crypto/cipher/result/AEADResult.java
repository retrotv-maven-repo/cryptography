package dev.retrotv.crypto.cipher.result;

/**
 * AEAD 암호화 결과를 담는 클래스 입니다.
 * @property data 암호화된 데이터
 * @property tag 인증 태그
 */
public class AEADResult extends Result {
    private final byte[] tag;

    public AEADResult(byte[] data, byte[] tag) {
        super(data);
        this.tag = tag;
    }

    public byte[] getTag() {
        return tag;
    }
}
