package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.StreamBlockCipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
import lombok.NonNull;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * OFB 암호화 모드 클래스 입니다.
 */
public class OFB extends StreamBlockCipherMode {
    public OFB(@NonNull BlockCipher blockCipher) {
        super(EMode.ECB, blockCipher);
        this.blockSize = getBlockSizeByAlgorithm(this.algorithm);
    }

    @Override
    public Result encrypt(@NonNull byte[] data, @NonNull Param params) throws CryptoFailException {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("OFB 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        OFBBlockCipher cipher = new OFBBlockCipher(this.engine, this.blockSize);
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
        cipher.init(true, parameters);

        return this.encryptBlock(data, cipher);
    }

    @Override
    public Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params) throws CryptoFailException {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("OFB 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        OFBBlockCipher cipher = new OFBBlockCipher(this.engine, this.blockSize);
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
        cipher.init(false, parameters);

        return this.decryptBlock(encryptedData, cipher);
    }
}
