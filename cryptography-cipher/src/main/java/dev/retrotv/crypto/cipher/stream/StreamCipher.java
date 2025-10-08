package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.TwoWayEncryption;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.exception.CryptoFailException;
import lombok.NonNull;

import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class StreamCipher implements TwoWayEncryption {
    protected org.bouncycastle.crypto.StreamCipher engine;

    /**
     * 스트림 암호화
     *
     * @param input 암호화할 스트림
     * @param output 암호화된 스트림이 저장될 스트림
     * @param params 암호화 파라미터
     */
    public abstract void encrypt(@NonNull InputStream input, @NonNull OutputStream output, @NonNull Param params);

    /**
     * 스트림 복호화
     *
     * @param input 암호화된 스트림
     * @param output 복호화된 스트림이 저장될 스트림
     * @param params 복호화 파라미터
     */
    public abstract void decrypt(@NonNull InputStream input, @NonNull OutputStream output, @NonNull Param params);

    protected void streamEncrypt(InputStream input, OutputStream output) {
        try (CipherOutputStream cos = new CipherOutputStream(output, this.engine)) {
            byte[] buffer = new byte[1024];
            int i = input.read(buffer);
            while (i != -1) {
                cos.write(buffer, 0, i);
                i = input.read(buffer);
            }
            cos.flush();
        } catch (IOException ex) {
            throw new CryptoFailException(ex);
        }
    }

    protected void streamDecrypt(InputStream input, OutputStream output) {
        try (CipherInputStream cis = new CipherInputStream(input, this.engine)) {
            byte[] buffer = new byte[1024];
            int i = cis.read(buffer);
            while (i != -1) {
                output.write(buffer, 0, i);
                i = cis.read(buffer);
            }
        } catch (IOException ex) {
            throw new CryptoFailException(ex);
        }
    }
}