package dev.retrotv.crypto.cipher.block;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import dev.retrotv.crypto.cipher.result.AEADResult;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.exception.CryptoFailException;

@SuppressWarnings("java:S1854")
public abstract class AEADCipherMode extends CipherMode {
    protected byte[] aad = null;

    /**
     * @param mode        암호화 모드
     * @param blockCipher 블록 암호화 클래스
     */
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

    protected AEADResult decryptBlock(byte[] encryptedData, AEADBlockCipher cipher) {
        byte[] originalData = new byte[cipher.getOutputSize(encryptedData.length)];
        int tam = cipher.processBytes(encryptedData, 0, encryptedData.length, originalData, 0);

        try {
            tam += cipher.doFinal(originalData, tam);
        } catch (InvalidCipherTextException e) {
            throw new CryptoFailException("CCM 인증 태그 생성 실패: " + e.getMessage(), e);
        }

        return new AEADResult(originalData, cipher.getMac());
    }
}
