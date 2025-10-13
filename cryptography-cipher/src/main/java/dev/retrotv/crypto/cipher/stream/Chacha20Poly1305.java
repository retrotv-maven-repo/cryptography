package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.AEADResult;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.AlgorithmNotFoundException;
import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.exception.GeneralException;
import lombok.NonNull;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Arrays;

@SuppressWarnings("squid:S5542") // Chacha20-Poly1305는 Padding이 필요없는 알고리즘임
public class Chacha20Poly1305 extends AEADStreamCipher {
    private static final String REQUIRED_MESSAGE = "ChaCha20 모드는 ParamsWithIV 객체를 요구합니다.";
    private static final String ALGORITHM = "ChaCha20-Poly1305";

    public Chacha20Poly1305() {
        Security.addProvider(new BouncyCastleProvider());

        try {
            this.cipher = Cipher.getInstance(ALGORITHM, "BC");
        } catch (NoSuchAlgorithmException ex) {
            throw new AlgorithmNotFoundException(ex);
        } catch (NoSuchPaddingException | NoSuchProviderException ex) {
            throw new GeneralException(ex);
        }
    }

    @Override
    public Result encrypt(@NonNull byte[] data, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException(REQUIRED_MESSAGE);
        }

        ParamWithIV paramWithIV = (ParamWithIV) params;
        SecretKeySpec key = new SecretKeySpec(paramWithIV.getKey(), "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(paramWithIV.getIv());

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            cipher.updateAAD(aad);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new CryptoFailException("잘못된 초기화벡터(IV) 혹은 IV를 지원하지 않는 알고리즘 입니다.", ex);
        } catch (InvalidKeyException ex) {
            throw new CryptoFailException("잘못된 암호화 키 입니다.", ex);
        }

        byte[] encryptedData;
        try {
            encryptedData = this.cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new GeneralException("이 예외는 기본적으로 Chacha20Poly1305 알고리즘에서 발생하지 않습니다.", ex);
        }

        if (encryptedData == null || encryptedData.length < 16) {
            throw new CryptoFailException("암호화가 올바르게 진행되지 않았습니다.");
        }

        byte[] tag = Arrays.copyOfRange(encryptedData, encryptedData.length - 16, encryptedData.length);

        return new AEADResult(encryptedData, tag);
    }

    @Override
    public void encrypt(@NonNull InputStream input, @NonNull OutputStream output, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException(REQUIRED_MESSAGE);
        }

        ParamWithIV paramWithIV = (ParamWithIV) params;
        SecretKeySpec key = new SecretKeySpec(paramWithIV.getKey(), "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(paramWithIV.getIv());

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            cipher.updateAAD(aad);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new CryptoFailException("잘못된 초기화벡터(IV) 혹은 IV를 지원하지 않는 알고리즘 입니다.", ex);
        } catch (InvalidKeyException ex) {
            throw new CryptoFailException("잘못된 암호화 키 입니다.", ex);
        }

        this.streamEncrypt(input, output);
    }

    @Override
    public Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException(REQUIRED_MESSAGE);
        }

        ParamWithIV paramWithIV = (ParamWithIV) params;
        SecretKeySpec key = new SecretKeySpec(paramWithIV.getKey(), "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(paramWithIV.getIv());

        try {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            cipher.updateAAD(aad);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new CryptoFailException("잘못된 초기화벡터(IV) 혹은 IV를 지원하지 않는 알고리즘 입니다.", ex);
        } catch (InvalidKeyException ex) {
            throw new CryptoFailException("잘못된 암호화 키 입니다.", ex);
        }

        byte[] originalData;
        try {
            originalData = this.cipher.doFinal(encryptedData);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new GeneralException("이 예외는 기본적으로 Chacha20Poly1305 알고리즘에서 발생하지 않습니다.", ex);
        }

        if (originalData == null || originalData.length < 16) {
            throw new CryptoFailException("암호화가 올바르게 진행되지 않았습니다.");
        }

        return new Result(originalData);
    }

    @Override
    public void decrypt(@NonNull InputStream input, @NonNull OutputStream output, @NonNull Param params) {
        if (!(params instanceof ParamWithIV)) {
            throw new IllegalArgumentException(REQUIRED_MESSAGE);
        }

        ParamWithIV paramWithIV = (ParamWithIV) params;
        SecretKeySpec key = new SecretKeySpec(paramWithIV.getKey(), "ChaCha20");
        IvParameterSpec iv = new IvParameterSpec(paramWithIV.getIv());

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            cipher.updateAAD(aad);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new CryptoFailException("잘못된 초기화벡터(IV) 혹은 IV를 지원하지 않는 알고리즘 입니다.", ex);
        } catch (InvalidKeyException ex) {
            throw new CryptoFailException("잘못된 암호화 키 입니다.", ex);
        }

        this.streamDecrypt(input, output);
    }
}
