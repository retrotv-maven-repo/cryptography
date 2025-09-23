package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * RC4 스트림 암호화 클래스 입니다.
 * @deprecated 해킹에 취약한 양방향 암호화 알고리즘 입니다. 더 높은 보안성을 지닌 알고리즘 사용을 권장합니다.
 */
@Deprecated
public class RC4 extends StreamCipher {
    public RC4() {
        this.engine = new RC4Engine();
    }

    @Override
    public Result encrypt(byte[] data, Param params) {
        this.engine.init(true, new KeyParameter(params.getKey()));
        byte[] encryptedData = new byte[data.length];
        this.engine.processBytes(data, 0, data.length, encryptedData, 0);
        
        return new Result(encryptedData);
    }

    @Override
    public void encrypt(InputStream input, OutputStream output, Param params) {
        this.engine.init(true, new KeyParameter(params.getKey()));
        this.streamEncrypt(input, output);
    }

    @Override
    public Result decrypt(byte[] encryptedData, Param params) {
        this.engine.init(false, new KeyParameter(params.getKey()));
        byte[] originalData = new byte[encryptedData.length];
        this.engine.processBytes(encryptedData, 0, encryptedData.length, originalData, 0);
        
        return new Result(originalData);
    }

    @Override
    public void decrypt(InputStream input, OutputStream output, Param params) {
        try {
            this.engine.init(false, new KeyParameter(params.getKey()));
            this.streamDecrypt(input, output);
        } catch (Exception ex) {
            throw new CryptoFailException(ex);
        }
    }
}
