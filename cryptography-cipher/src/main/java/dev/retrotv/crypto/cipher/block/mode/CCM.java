package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.CipherMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.AEADResult;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import dev.retrotv.crypto.cipher.enums.EMode;

/**
 * CCM 암호화 모드 클래스 입니다.
 */
public class CCM extends CipherMode {
    private byte[] aad = null;
    private static final int DEFAULT_TAG_LENGTH = 16;
    private static int tLen = DEFAULT_TAG_LENGTH;

    /**
     * CCM 모드 생성자
     *
     * @param blockCipher 블록 암호화 클래스
     */
    public CCM(BlockCipher blockCipher) {
        super(EMode.CCM, blockCipher);
    }

    @Override
    public Result encrypt(byte[] data, Param params) throws CryptoFailException {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("CCM 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        int macSize = tLen * 8;
        CCMModeCipher cipher = CCMBlockCipher.newInstance(this.engine);
        cipher.init(true, new AEADParameters(new KeyParameter(paramWithIV.getKey()), macSize, paramWithIV.getIv(), this.aad));

        byte[] encryptedData = new byte[cipher.getOutputSize(data.length)];
        int tam = cipher.processBytes(data, 0, data.length, encryptedData, 0);

        try {
            // doFinal을 해야 tag까지 정상적으로 생성된다
            tam += cipher.doFinal(encryptedData, tam);
        } catch (InvalidCipherTextException e) {
            throw new CryptoFailException("CCM 인증 태그 생성 실패: " + e.getMessage(), e);
        }

        return new AEADResult(encryptedData, cipher.getMac());
    }

    @Override
    public Result decrypt(byte[] encryptedData, Param params) throws CryptoFailException {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("CCM 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        int macSize = tLen * 8;
        CCMModeCipher cipher = CCMBlockCipher.newInstance(this.engine);
        cipher.init(false, new AEADParameters(new KeyParameter(paramWithIV.getKey()), macSize, paramWithIV.getIv(), this.aad));

        byte[] originalData = new byte[cipher.getOutputSize(encryptedData.length)];
        int tam = cipher.processBytes(encryptedData, 0, encryptedData.length, originalData, 0);

        try {
            tam += cipher.doFinal(originalData, tam);
        } catch (InvalidCipherTextException e) {
            throw new CryptoFailException("CCM 인증 태그 생성 실패: " + e.getMessage(), e);
        }

        return new AEADResult(originalData, cipher.getMac());
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
     * 인증 태그의 길이를 업데이트 합니다.
     *
     * @param tagLength 인증 태그의 길이 (2의 배수, 4 ~ 16 Byte)
     */
    public void updateTagLength(int tagLength) {
        if (tagLength % 2 != 0) {
            throw new IllegalArgumentException("인증태그의 길이는 2의 배수여야 합니다.");
        }
        if (tagLength < 4 || tagLength > 16) {
            throw new IllegalArgumentException("인증태그의 길이는 4 ~ 16Byte만 허용됩니다.");
        }
        tLen = tagLength;
    }
}
