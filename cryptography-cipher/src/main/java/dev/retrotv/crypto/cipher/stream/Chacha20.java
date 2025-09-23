package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * ChaCha20 스트림 암호화 클래스 입니다.
 */
public class Chacha20 extends StreamCipher {
    private static final String REQUIRED_MESSAGE = "ChaCha20 모드는 ParamsWithIV 객체를 요구합니다.";

    public Chacha20() {
        this.engine = new ChaChaEngine(20);
    }

    @Override
    public Result encrypt(byte[] data, Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException(REQUIRED_MESSAGE);
        }

        ParamWithIV paramWithIV = (ParamWithIV) params;
        this.engine.init(true, new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv()));
        byte[] encryptedData = new byte[data.length];
        this.engine.processBytes(data, 0, data.length, encryptedData, 0);
        
        return new Result(encryptedData);
    }

    @Override
    public void encrypt(InputStream input, OutputStream output, Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException(REQUIRED_MESSAGE);
        }

        ParamWithIV paramWithIV = (ParamWithIV) params;
        this.engine.init(true, new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv()));
        this.streamEncrypt(input, output);
    }

    @Override
    public Result decrypt(byte[] encryptedData, Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException(REQUIRED_MESSAGE);
        }

        ParamWithIV paramWithIV = (ParamWithIV) params;
        this.engine.init(false, new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv()));
        byte[] originalData = new byte[encryptedData.length];
        this.engine.processBytes(encryptedData, 0, encryptedData.length, originalData, 0);
        
        return new Result(originalData);
    }

    @Override
    public void decrypt(InputStream input, OutputStream output, Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException(REQUIRED_MESSAGE);
        }
        
        try {
            ParamWithIV paramWithIV = (ParamWithIV) params;
            this.engine.init(false, new ParametersWithIV(new KeyParameter(paramWithIV.getKey()), paramWithIV.getIv()));
            CipherInputStream cis = new CipherInputStream(input, this.engine);
            byte[] buffer = new byte[1024];
            int i = cis.read(buffer);
            while (i != -1) {
                output.write(buffer, 0, i);
                i = cis.read(buffer);
            }
            cis.close();
        } catch (Exception ex) {
            throw new CryptoFailException(ex);
        }
    }
}
