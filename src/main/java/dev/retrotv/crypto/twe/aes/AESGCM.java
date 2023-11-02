package dev.retrotv.crypto.twe.aes;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.exception.WrongKeyLengthException;
import dev.retrotv.crypto.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

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

import static dev.retrotv.enums.CipherAlgorithm.AESGCM;

public class AESGCM extends AES implements ParameterSpecGenerator<GCMParameterSpec> {
    protected static final int GCM_IV_LENGTH = 12;
    protected static final int GCM_TAG_LENGTH = 16;
    protected String aad = null;

    public AESGCM(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = AESGCM;
    }

    @Override
    public byte[] encrypt(byte[] data, Key key, AlgorithmParameterSpec spec) throws CryptoFailException {
        String algorithmName = algorithm.label() + "/" + padding.label();

        try {
            Cipher cipher = Cipher.getInstance(algorithmName);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            if (aad != null) {
                cipher.updateAAD(aad.getBytes());
            }

            return cipher.doFinal(data);
        } catch (BadPaddingException e) {
            throw new CryptoFailException(BAD_PADDING_EXCEPTION_MESSAGE, e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoFailException(ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoFailException(INVALID_ALGORITHM_PARAMETER_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptoFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (NoSuchPaddingException e) {
            throw new CryptoFailException(NO_SUCH_PADDING_EXCEPTION_MESSAGE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, Key key, AlgorithmParameterSpec spec) throws CryptoFailException {
        String algorithmName = algorithm.label() + "/" + padding.label();

        try {
            Cipher cipher = Cipher.getInstance(algorithmName);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            if (aad != null) {
                cipher.updateAAD(aad.getBytes());
            }

            return cipher.doFinal(encryptedData);
        } catch (BadPaddingException e) {
            throw new CryptoFailException(BAD_PADDING_EXCEPTION_MESSAGE, e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoFailException(ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoFailException(INVALID_ALGORITHM_PARAMETER_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptoFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (NoSuchPaddingException e) {
            throw new CryptoFailException(NO_SUCH_PADDING_EXCEPTION_MESSAGE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    public void updateAAD(String aad) {
        this.aad = aad;
    }

    @Override
    public GCMParameterSpec generateSpec() {
        return new GCMParameterSpec(GCM_TAG_LENGTH * 8, SecureRandomUtil.generate(GCM_IV_LENGTH));
    }
}
