package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.PaddedBlockCipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import lombok.NonNull;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * CBC 암호화 모드 클래스 입니다.
 */
public class CBC extends PaddedBlockCipherMode {

    /**
     * CBC 모드 객체를 생성합니다.
     * 
     * @param blockCipher 사용할 블록 암호 객체
     */
    public CBC(@NonNull BlockCipher blockCipher) {
        super(EMode.CBC, blockCipher);
    }

    @Override
    public Result encrypt(@NonNull byte[] data, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("CBC 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(this.engine));
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
        cipher.init(true, parameters);

        return this.encryptBlock(data, cipher);
    }

    @Override
    public Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("CBC 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(this.engine));
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv());
        cipher.init(false, parameters);

        return this.decryptBlock(encryptedData, cipher);
    }
}
