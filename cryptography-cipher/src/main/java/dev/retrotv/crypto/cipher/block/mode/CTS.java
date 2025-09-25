package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.BlockCipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
import lombok.NonNull;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * CTS 암호화 모드 클래스 입니다.
 */
public class CTS extends BlockCipherMode {
    public CTS(@NonNull BlockCipher blockCipher) {
        super(EMode.CTS, blockCipher);
    }

    @Override
    public Result encrypt(@NonNull byte[] data, @NonNull Param params) {
        CipherParameters parameters = getParameters(params);
        CTSBlockCipher cipher = new CTSBlockCipher(this.engine);
        cipher.init(true, parameters);

        byte[] encryptedData = new byte[data.length];
        int len = cipher.processBytes(data, 0, data.length, encryptedData, 0);
        try {
            cipher.doFinal(encryptedData, len);
        } catch (InvalidCipherTextException ex) {
            throw new CryptoFailException(ex);
        }

        return new Result(encryptedData);
    }

    @Override
    public Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params) {
        CipherParameters parameters = getParameters(params);
        CTSBlockCipher cipher = new CTSBlockCipher(this.engine);
        cipher.init(false, parameters);

        byte[] originalData = new byte[encryptedData.length];
        int len = cipher.processBytes(encryptedData, 0, encryptedData.length, originalData, 0);
        try {
            cipher.doFinal(originalData, len);
        } catch (DataLengthException | IllegalStateException | InvalidCipherTextException ex) {
            throw new CryptoFailException(ex);
        }

        return new Result(originalData);
    }

    public void useCBCMode() {
        this.engine = CBCBlockCipher.newInstance(this.engine);
    }

    private CipherParameters getParameters(Param params) {
        if (params instanceof ParamWithIV) {
            ParamWithIV paramWithIV = (ParamWithIV) params;
            if (paramWithIV.getIv() == null) {
                return new KeyParameter(paramWithIV.getKey());
            } else {
                return new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
            }
        } else {
            return new KeyParameter(params.getKey());
        }
    }
}
