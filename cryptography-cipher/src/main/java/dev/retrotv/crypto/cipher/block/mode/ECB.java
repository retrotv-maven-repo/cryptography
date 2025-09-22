package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.CipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * ECB 암호화 모드 클래스 입니다.
 */
public class ECB extends CipherMode {

    public ECB(BlockCipher blockCipher) {
        super(EMode.ECB, blockCipher);
    }

    @Override
    public Result encrypt(byte[] data, Param params) throws CryptoFailException {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(this.engine);
        cipher.init(true, new KeyParameter(params.getKey()));

        byte[] encryptedData = new byte[cipher.getOutputSize(data.length)];
        int tam = cipher.processBytes(data, 0, data.length, encryptedData, 0);
        try {
            tam += cipher.doFinal(encryptedData, tam);
        } catch (Exception e) {
            throw new CryptoFailException(e);
        }

        return new Result(encryptedData);
    }

    @Override
    public Result decrypt(byte[] encryptedData, Param params) throws CryptoFailException {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(this.engine);
        cipher.init(false, new KeyParameter(params.getKey()));

        byte[] outputData = new byte[cipher.getOutputSize(encryptedData.length)];
        int tam = cipher.processBytes(encryptedData, 0, encryptedData.length, outputData, 0);
        int finalLen;
        try {
            finalLen = cipher.doFinal(outputData, tam);
        } catch (Exception e) {
            throw new CryptoFailException(e);
        }
        byte[] originalData = new byte[tam + finalLen];
        System.arraycopy(outputData, 0, originalData, 0, tam + finalLen);

        return new Result(originalData);
    }
}
