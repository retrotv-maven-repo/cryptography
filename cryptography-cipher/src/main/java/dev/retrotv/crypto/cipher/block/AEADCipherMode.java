package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.enums.EMode;

public abstract class AEADCipherMode extends CipherMode {
    protected byte[] aad = null;

    protected AEADCipherMode(EMode mode, BlockCipher blockCipher) {
        super(mode, blockCipher);
    }

    /**
     * 추가 인증 데이터를 업데이트 합니다.
     *
     * @param aad 추가 인증 데이터
     */
    public void updateAAD(byte[] aad) {
        this.aad = aad;
    }

    /**
     * 태그 길이를 업데이트 합니다.
     *
     * @param tagLength 태그 길이 (바이트 단위)
     */
    public abstract void updateTagLength(int tagLength);
}
