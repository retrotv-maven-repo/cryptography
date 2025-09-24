package dev.retrotv.crypto.cipher.block.mode;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.PaddedBlockCipherMode;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.result.Result;
import lombok.NonNull;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * ECB 암호화 모드 클래스 입니다.
 */
public class ECB extends PaddedBlockCipherMode {

    /**
     * ECB 모드 객체를 생성합니다.
     * 
     * @param blockCipher 사용할 블록 암호 객체
     */
    public ECB(@NonNull BlockCipher blockCipher) {
        super(EMode.ECB, blockCipher);
    }

    @Override
    public Result encrypt(@NonNull byte[] data, @NonNull Param params) {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(this.engine);
        CipherParameters parameters = new KeyParameter(params.getKey());
        cipher.init(true, parameters);

        return this.encryptBlock(data, cipher);
    }

    @Override
    public Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params) {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(this.engine);
        CipherParameters parameters = new KeyParameter(params.getKey());
        cipher.init(false, parameters);

        return this.decryptBlock(encryptedData, cipher);
    }
}
