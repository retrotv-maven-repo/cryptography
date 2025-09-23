package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.PaddedBlockCipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * CBC 암호화 모드 클래스 입니다.
 */
public class CBC extends PaddedBlockCipherMode {
    public CBC(BlockCipher blockCipher) {
        super(EMode.CBC, blockCipher);
    }

    @Override
    public Result encrypt(byte[] data, Param params) throws CryptoFailException {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("CBC 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(this.engine));
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
        cipher.init(true, parameters);

        byte[] encryptedData = this.blockEncrypt(data, params, cipher);
        return new Result(encryptedData);
    }

    @Override
    public Result decrypt(byte[] encryptedData, Param params) throws CryptoFailException {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("CBC 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(this.engine));
        cipher.init(false, new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv()));

        byte[] originalData = this.blockDecrypt(encryptedData, params, cipher);
        return new Result(originalData);
    }
}
