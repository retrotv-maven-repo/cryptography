package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.CipherMode;
import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * OFB 암호화 모드 클래스 입니다.
 */
public class OFB extends CipherMode {
    private final int blockSize;

    public OFB(BlockCipher blockCipher) {
        super(EMode.ECB, blockCipher);
        this.blockSize = getBlockSizeByAlgorithm(this.algorithm);
    }

    private int getBlockSizeByAlgorithm(ECipher algorithm) {
        switch (algorithm) {
            case AES:
            case ARIA:
            case LEA:
            case SEED:
            case SERPENT:
                return 128;
            case DES:
            case TRIPLE_DES:
                return 64;
            default:
                throw new IllegalArgumentException("사용할 수 없는 알고리즘 입니다.");
        }
    }

    @Override
    public Result encrypt(byte[] data, Param params) throws CryptoFailException {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("OFB 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        OFBBlockCipher cipher = new OFBBlockCipher(this.engine, this.blockSize);
        cipher.init(true, new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv()));

        byte[] encryptedData = new byte[data.length];
        cipher.processBytes(data, 0, data.length, encryptedData, 0);

        return new Result(encryptedData);
    }

    @Override
    public Result decrypt(byte[] encryptedData, Param params) throws CryptoFailException {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException("OFB 모드는 ParamsWithIV 객체를 요구합니다.");
        }
        ParamWithIV paramWithIV = (ParamWithIV) params;

        OFBBlockCipher cipher = new OFBBlockCipher(this.engine, this.blockSize);
        cipher.init(false, new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv()));

        byte[] originalData = new byte[encryptedData.length];
        cipher.processBytes(encryptedData, 0, encryptedData.length, originalData, 0);

        return new Result(originalData);
    }
}
