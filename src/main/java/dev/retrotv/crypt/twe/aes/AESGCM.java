package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public abstract class AESGCM extends AES implements ParameterSpecGenerator<GCMParameterSpec> {
    protected static final int GCM_IV_LENGTH = 12;
    protected static final int GCM_TAG_LENGTH = 16;
    protected String aad = null;

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException {
        try {
            log.debug("선택된 알고리즘: {}", algorithm.label());
            Cipher cipher = Cipher.getInstance(algorithm.label());
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            if (aad != null) {
                cipher.updateAAD(aad.getBytes());
            }

            return cipher.doFinal(data);
        } catch (BadPaddingException e) {
            throw new CryptFailException(BAD_PADDING_EXCEPTION_MESSAGE, e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptFailException(ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptFailException(INVALID_ALGORITHM_PARAMETER_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (NoSuchPaddingException e) {
            throw new CryptFailException(NO_SUCH_PADDING_EXCEPTION_MESSAGE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm.label());
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            if (aad != null) {
                cipher.updateAAD(aad.getBytes());
            }

            return cipher.doFinal(encryptedData);
        } catch (BadPaddingException e) {
            throw new CryptFailException(BAD_PADDING_EXCEPTION_MESSAGE, e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptFailException(ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptFailException(INVALID_ALGORITHM_PARAMETER_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (NoSuchPaddingException e) {
            throw new CryptFailException(NO_SUCH_PADDING_EXCEPTION_MESSAGE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    public void updateAAD(@NonNull String aad) {
        this.aad = aad;
    }

    @Override
    public GCMParameterSpec generateSpec() {
        return new GCMParameterSpec(GCM_TAG_LENGTH * 8, SecureRandomUtil.generate(GCM_IV_LENGTH));
    }
}
