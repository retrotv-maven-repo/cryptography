package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.CipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * CTS 암호화 모드 클래스 입니다.
 */
public class CTS extends CipherMode {
    public CTS(BlockCipher blockCipher) {
        super(EMode.CTS, blockCipher);
    }

    @Override
    public Result encrypt(byte[] data, Param params) {
        CipherParameters parameters;
        if (params instanceof ParamWithIV) {
            ParamWithIV paramWithIV = (ParamWithIV) params;
            if (paramWithIV.getIv() == null) {
                parameters = new KeyParameter(paramWithIV.getKey());
            } else {
                parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
            }
        } else {
            parameters = new KeyParameter(params.getKey());
        }

        CTSBlockCipher cipher = new CTSBlockCipher(this.engine);
        cipher.init(true, parameters);

        byte[] encryptedData = new byte[data.length];
        int len = cipher.processBytes(data, 0, data.length, encryptedData, 0);
        try {
            cipher.doFinal(encryptedData, len);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new Result(encryptedData);
    }

    @Override
    public Result decrypt(byte[] encryptedData, Param params) {
        CipherParameters parameters;
        if (params instanceof ParamWithIV) {
            ParamWithIV paramWithIV = (ParamWithIV) params;
            if (paramWithIV.getIv() == null) {
                parameters = new KeyParameter(paramWithIV.getKey());
            } else {
                parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
            }
        } else {
            parameters = new KeyParameter(params.getKey());
        }

        CTSBlockCipher cipher = new CTSBlockCipher(this.engine);
        cipher.init(false, parameters);

        byte[] originalData = new byte[encryptedData.length];
        int len = cipher.processBytes(encryptedData, 0, encryptedData.length, originalData, 0);
        try {
            cipher.doFinal(originalData, len);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new Result(originalData);
    }

    public void useCBCMode() {
        this.engine = CBCBlockCipher.newInstance(this.engine);
    }
}
