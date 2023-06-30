package dev.retrotv.crypt.twe.des;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.KeyGenerator;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.enums.Algorithm;
import lombok.NonNull;

public abstract class DES implements TwoWayEncryption, KeyGenerator {
    protected Algorithm algorithm;

    protected static final String BAD_PADDING_EXCEPTION_MESSAGE =
            "BadPaddingException: "
          + "\n암호화 시 사용한 키와 일치하지 않습니다.";

    protected static final String ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE =
            "IllegalBlockSizeException: "
          + "\n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.";

    protected static final String INVALID_ALGORITHM_PARAMETER_EXCEPTION_MESSAGE =
            "InvalidAlgorithmParameterException: "
          + "\n%JAVA_HOME%\\jre\\lib\\security\\cacerts 파일이 존재하지 않거나 내부에 데이터가 존재하지 않는지 확인하십시오.";

    protected static final String INVALID_KEY_EXCEPTION_MESSAGE =
            "InvalidKeyException: "
          + "\n1. 암호화 키는 각각 16/24/32 byte 길이의 키만 사용할 수 있습니다."
          + "\n2. JDK 8u161 이전 버전 및 Oracle JDK를 사용하는 경우, 16 byte 이상의 키 사용이 제한될 수 있습니다."
          + "\n   이에 대해서는 InvalidKeyException 무제한 강도 정책(Unlimited Strength Jurisdiction Policy)을 참조하십시오.";

    protected static final String NO_SUCH_PADDING_EXCEPTION_MESSAGE =
            "NoSuchPaddingException: "
          + "\n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.";

    protected static final String NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE =
            "NoSuchAlgorithmException: "
          + "\n지원하지 않는 암호화 알고리즘 입니다.";

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull byte[] key, byte[] iv) throws CryptFailException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm.label());

            switch (algorithm) {
                case DESECB_PADDING, DESECB_NO_PADDING:
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
                    break;
                case DESCBC_PADDING, DESCBC_NO_PADDING:
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"), new IvParameterSpec(iv));
                    break;
                case TRIPLE_DESECB_PADDING, TRIPLE_DESECB_NO_PADDING:
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
                    break;
                case TRIPLE_DESCBC_PADDING, TRIPLE_DESCBC_NO_PADDING:
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
                    break;
                default:
                    throw new NoSuchAlgorithmException("사용되지 않는 암호화 알고리즘 입니다.");
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
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull byte[] key, byte[] iv) throws CryptFailException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm.label());

            switch (algorithm) {
                case DESECB_PADDING, DESECB_NO_PADDING:
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DES"));
                    break;
                case DESCBC_PADDING, DESCBC_NO_PADDING:
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DES"), new IvParameterSpec(iv));
                    break;
                case TRIPLE_DESECB_PADDING, TRIPLE_DESECB_NO_PADDING:
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "TripleDES"));
                    break;
                case TRIPLE_DESCBC_PADDING, TRIPLE_DESCBC_NO_PADDING:
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "TripleDES"), new IvParameterSpec(iv));
                    break;
                default:
                    throw new NoSuchAlgorithmException("사용되지 않는 암호화 알고리즘 입니다.");
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
}
