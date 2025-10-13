package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.exception.CryptoFailException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class AEADStreamCipher extends StreamCipher {
    protected Cipher cipher;
    protected byte[] aad = null;

    /**
     * 추가 인증 데이터를 업데이트 합니다.
     *
     * @param aad 추가 인증 데이터
     */
    public void updateAAD(byte[] aad) {
        this.aad = aad;
    }

    @Override
    protected void streamEncrypt(InputStream input, OutputStream output) {
        try (CipherOutputStream cos = new CipherOutputStream(output, this.cipher)) {
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

    @Override
    protected void streamDecrypt(InputStream input, OutputStream output) {
        try (CipherInputStream cis = new CipherInputStream(input, this.cipher)) {
            byte[] buffer = new byte[1024];
            int i = cis.read(buffer);
            while (i != -1) {
                output.write(buffer, 0, i);
                i = cis.read(buffer);
            }
            output.flush();
        } catch (IOException ex) {
            throw new CryptoFailException(ex);
        }
    }
}