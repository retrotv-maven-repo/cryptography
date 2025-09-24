package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.StreamBlockCipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import lombok.NonNull;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * CFB 암호화 모드 클래스 입니다.
 */
public class CFB extends StreamBlockCipherMode {
    public CFB(@NonNull BlockCipher blockCipher) {
        super(EMode.CFB, blockCipher);
        this.blockSize = getBlockSizeByAlgorithm(this.algorithm);
    }

    @Override
    public Result encrypt(@NonNull byte[] data, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("CFB 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        CFBModeCipher cipher = CFBBlockCipher.newInstance(this.engine, this.blockSize);
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
        cipher.init(true, parameters);

        return this.encryptBlock(data, cipher);
    }

    @Override
    public Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("CFB 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        CFBModeCipher cipher = CFBBlockCipher.newInstance(this.engine, this.blockSize);
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
        cipher.init(false, parameters);

        return this.decryptBlock(encryptedData, cipher);
    }
}
