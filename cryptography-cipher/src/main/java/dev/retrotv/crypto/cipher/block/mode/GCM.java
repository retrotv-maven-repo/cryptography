package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.AEADBlockCipherMode;
import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.AEADResult;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
import lombok.NonNull;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * GCM 암호화 모드 클래스 입니다.
 */
@SuppressWarnings("java:S1854")
public class GCM extends AEADBlockCipherMode {
    private static final int DEFAULT_TAG_LENGTH = 16;
    private int tLen = DEFAULT_TAG_LENGTH;

    public GCM(@NonNull BlockCipher blockCipher) {
        super(EMode.ECB, blockCipher);
    }

    @Override
    public Result encrypt(@NonNull byte[] data, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("GCM 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        int macSize = tLen * 8;
        GCMModeCipher cipher = GCMBlockCipher.newInstance(this.engine);
        CipherParameters parameters = new AEADParameters(new KeyParameter(paramWithIV.getKey()), macSize, paramWithIV.getIv(), this.aad);
        cipher.init(true, parameters);

        byte[] outputData = new byte[cipher.getOutputSize(data.length)];
        int tam = cipher.processBytes(data, 0, data.length, outputData, 0);

        try {
            tam += cipher.doFinal(outputData, tam);
        } catch (InvalidCipherTextException ex) {
            throw new CryptoFailException("GCM 인증 태그 생성 실패", ex);
        }

        byte[] encryptedData = new byte[tam];
        System.arraycopy(outputData, 0, encryptedData, 0, encryptedData.length);

        return new AEADResult(encryptedData, cipher.getMac());
    }

    @Override
    public Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("GCM 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        int macSize = tLen * 8;
        GCMModeCipher cipher = GCMBlockCipher.newInstance(this.engine);
        CipherParameters parameters = new AEADParameters(new KeyParameter(paramWithIV.getKey()), macSize, paramWithIV.getIv(), this.aad);
        cipher.init(false, parameters);

        return this.decryptBlock(encryptedData, cipher);
    }

    /**
     * 인증 태그의 길이를 업데이트 합니다.
     *
     * @param tagLength 인증 태그의 길이 (12 ~ 16 Byte)
     */
    @Override
    public void updateTagLength(int tagLength) {
        if (tagLength < 12 || tagLength > 16) {
            throw new IllegalArgumentException("인증태그의 길이는 12 ~ 16Byte만 허용됩니다.");
        }
        tLen = tagLength;
    }
}
