package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.result.Result;

import lombok.NonNull;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

@SuppressWarnings("java:S1854")
public abstract class PaddedBlockCipherMode extends BlockCipherMode {
    protected PaddedBlockCipherMode(EMode mode, BlockCipher blockCipher) {
        super(mode, blockCipher);
    }

    protected Result encryptBlock(byte[] data, @NonNull PaddedBufferedBlockCipher cipher) {
        if (data == null) {
            throw new NullPointerException("암호화 할 데이터가 존재하지 않습니다.");
        }

        byte[] encryptedData = new byte[cipher.getOutputSize(data.length)];
        int tam = cipher.processBytes(data, 0, data.length, encryptedData, 0);
        try {
            tam += cipher.doFinal(encryptedData, tam);
        } catch (InvalidCipherTextException ex) {
            throw new CryptoFailException(ex);
        }

        return new Result(encryptedData);
    }

    protected Result decryptBlock(byte[] encryptedData, @NonNull PaddedBufferedBlockCipher cipher) {
        if (encryptedData == null) {
            throw new NullPointerException("복호화 할 데이터가 존재하지 않습니다.");
        }

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

        return new Result(originalData);
    }
}