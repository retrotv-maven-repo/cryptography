package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.cipher.enums.EMode;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

@SuppressWarnings("java:S1854")
public abstract class PaddedBlockCipherMode extends CipherMode {
    protected PaddedBlockCipherMode(EMode mode, BlockCipher blockCipher) {
        super(mode, blockCipher);
    }

    protected byte[] encryptBlock(byte[] data, PaddedBufferedBlockCipher cipher) {
        byte[] encryptedData = new byte[cipher.getOutputSize(data.length)];
        int tam = cipher.processBytes(data, 0, data.length, encryptedData, 0);
        try {
            tam += cipher.doFinal(encryptedData, tam);
        } catch (InvalidCipherTextException ex) {
            throw new CryptoFailException(ex);
        }

        return encryptedData;
    }

    protected byte[] decryptBlock(byte[] encryptedData, PaddedBufferedBlockCipher cipher) {
        byte[] outputData = new byte[cipher.getOutputSize(encryptedData.length)];
        int tam = cipher.processBytes(encryptedData, 0, encryptedData.length, outputData, 0);
        int finalLen;
        try {
            finalLen = cipher.doFinal(outputData, tam);
        } catch (InvalidCipherTextException ex) {
            throw new CryptoFailException(ex);
        }
        byte[] originalData = new byte[tam + finalLen];
        System.arraycopy(outputData, 0, originalData, 0, tam + finalLen);

        return originalData;
    }
}