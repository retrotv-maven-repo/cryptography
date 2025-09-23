package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.PaddedBlockCipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * ECB 암호화 모드 클래스 입니다.
 */
public class ECB extends PaddedBlockCipherMode {

    public ECB(BlockCipher blockCipher) {
        super(EMode.ECB, blockCipher);
    }

    @Override
    public Result encrypt(byte[] data, Param params) throws CryptoFailException {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(this.engine);
        CipherParameters parameters = new KeyParameter(params.getKey());
        cipher.init(true, parameters);

        byte[] encryptedData = this.blockEncrypt(data, params, cipher);
        return new Result(encryptedData);
    }

    @Override
    public Result decrypt(byte[] encryptedData, Param params) throws CryptoFailException {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(this.engine);
        cipher.init(false, new KeyParameter(params.getKey()));

        byte[] originalData = this.blockDecrypt(encryptedData, params, cipher);
        return new Result(originalData);
    }
}
