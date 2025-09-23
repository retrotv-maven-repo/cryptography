package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.cipher.enums.EMode;

import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

public abstract class PaddedBlockCipherMode extends CipherMode {
    protected PaddedBlockCipherMode(EMode mode, BlockCipher blockCipher) {
        super(mode, blockCipher);
    }

    protected byte[] blockEncrypt(byte[] data, Param params, PaddedBufferedBlockCipher cipher) {
        byte[] encryptedData = new byte[cipher.getOutputSize(data.length)];
        int tam = cipher.processBytes(data, 0, data.length, encryptedData, 0);
        try {
            tam += cipher.doFinal(encryptedData, tam);
        } catch (Exception e) {
            throw new CryptoFailException(e);
        }

        return encryptedData;
    }
}