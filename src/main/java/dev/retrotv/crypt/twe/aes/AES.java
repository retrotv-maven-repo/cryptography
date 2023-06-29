package dev.retrotv.crypt.twe.aes;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.CommonMessageUtil;
import lombok.NonNull;

public abstract class AES implements TwoWayEncryption {
    protected static final Logger log = LogManager.getLogger();
    protected static final CommonMessageUtil commonMessageUtil = new CommonMessageUtil();

    protected int keyLength;
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

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException data 혹은 key, initialization vector가 null인 경우 발생
     * @throws CryptFailException 복호화 시 사용한 키가, 암호화 할 때 사용한 키와 일치하지 않는 경우 발생
     * @throws CryptFailException 암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도할 경우 발생
     * @throws CryptFailException %JAVA_HOME%\jre\lib\security\cacerts 파일이 존재하지 않거나 내부에 데이터가 존재하지 않는 경우 발생
     * @throws CryptFailException 암호화 키 값이 각각 16/24/32 byte가 아니거나, 키 값이 16 byte를 초과하면서 무제한 강도 정책이 활성화 되지 않은 경우 발생
     * @throws CryptFailException 지원되지 않거나, 부정확한 포맷으로 패딩된 데이터 암복호화를 시도하려고 할 때 발생
     * @param data 암호화 할 데이터
     * @param key 암호화 시, 사용할 키
     * @param iv 초기화 벡터
     * @return 암호화 된 데이터
     */
    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull byte[] key, byte[] iv) throws CryptFailException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm.label());

            switch (algorithm) {
                case AESECB128_PADDING, AESECB192_PADDING, AESECB256_PADDING:
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
                    break;
                case AESCBC128_PADDING, AESCBC192_PADDING, AESCBC256_PADDING:
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                    break;
                case AESGCM128_NO_PADDING, AESGCM192_NO_PADDING, AESGCM256_NO_PADDING:
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
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

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException encryptedData 혹은 key, initialization vector가 null인 경우 발생
     * @throws CryptFailException 복호화 시 사용한 키가, 암호화 할 때 사용한 키와 일치하지 않는 경우 발생
     * @throws CryptFailException 암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도할 경우 발생
     * @throws CryptFailException %JAVA_HOME%\jre\lib\security\cacerts 파일이 존재하지 않거나 내부에 데이터가 존재하지 않는 경우 발생
     * @throws CryptFailException 암호화 키 값이 각각 16/24/32 byte가 아니거나, 키 값이 16 byte를 초과하면서 무제한 강도 정책이 활성화 되지 않은 경우 발생
     * @throws CryptFailException 지원되지 않거나, 부정확한 포맷으로 패딩된 데이터 암복호화를 시도하려고 할 때 발생
     * @param encryptedData 암호화 된 데이터
     * @param key 복호화 시, 사용할 키
     * @param iv 초기화 벡터
     * @return 복호화 된 데이터
     */
    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull byte[] key, byte[] iv) throws CryptFailException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm.label());

            switch (algorithm) {
                case AESECB128_PADDING, AESECB192_PADDING, AESECB256_PADDING:
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                    break;
                case AESCBC128_PADDING, AESCBC192_PADDING, AESCBC256_PADDING:
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                    break;
                case AESGCM128_NO_PADDING, AESGCM192_NO_PADDING, AESGCM256_NO_PADDING:
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
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

    @Override
    public byte[] generateKey() throws KeyGenerateException {
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[keyLength];
        sr.nextBytes(key);

        return key;
    }
}
