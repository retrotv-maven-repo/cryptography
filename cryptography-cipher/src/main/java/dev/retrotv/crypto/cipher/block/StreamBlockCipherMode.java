package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.AlgorithmNotFoundException;

import org.bouncycastle.crypto.StreamCipher;

public abstract class StreamBlockCipherMode extends BlockCipherMode {
    protected int blockSize;

    /**
     * @param mode        암호화 모드
     * @param blockCipher 블록 암호화 클래스
     */
    protected StreamBlockCipherMode(EMode mode, BlockCipher blockCipher) {
        super(mode, blockCipher);
    }

    protected int getBlockSizeByAlgorithm(ECipher algorithm) {
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
                throw new AlgorithmNotFoundException("지원하지 않는 알고리즘 입니다.");
        }
    }

    protected Result encryptBlock(byte[] data, StreamCipher cipher) {
        byte[] encryptedData = new byte[data.length];
        cipher.processBytes(data, 0, data.length, encryptedData, 0);

        return new Result(encryptedData);
    }

    protected Result decryptBlock(byte[] encryptedData, StreamCipher cipher) {
        byte[] originalData = new byte[encryptedData.length];
        cipher.processBytes(encryptedData, 0, encryptedData.length, originalData, 0);

        return new Result(originalData);
    }
}
