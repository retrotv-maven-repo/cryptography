package dev.retrotv.crypt.twe.aes;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.enums.SecurityStrength;
import lombok.NonNull;

public abstract class AESGCM extends AES {
    protected static final int GCM_IV_LENGTH = 12;
    protected static final int GCM_TAG_LENGTH = 16;
    
    /**
     * 문자열을 암호화 하고, 암호화 된 문자열을 반환 합니다.
     *
     * @throws CryptFailException text 혹은 key, initialization vector가 null인 경우 발생
     * @throws CryptFailException 복호화 시 사용한 키가, 암호화 할 때 사용한 키와 일치하지 않는 경우 발생
     * @throws CryptFailException 암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도할 경우 발생
     * @throws CryptFailException %JAVA_HOME%\jre\lib\security\cacerts 파일이 존재하지 않거나 내부에 데이터가 존재하지 않는 경우 발생
     * @throws CryptFailException 암호화 키 값이 각각 16/24/32 byte가 아니거나, 키 값이 16 byte를 초과하면서 무제한 강도 정책이 활성화 되지 않은 경우 발생
     * @throws CryptFailException 지원되지 않거나, 부정확한 포맷으로 패딩된 데이터 암복호화를 시도하려고 할 때 발생
     * @param text 암호화 할 문자열
     * @param key 암호화 시, 사용할 키
     * @param iv 초기화 벡터
     * @return 암호화 된 문자열
     */
    public String encrypt(@NonNull String text, @NonNull byte[] key, @NonNull GCMParameterSpec spec) throws CryptFailException {
        byte[] data = text.getBytes();
        return new String(Base64.getEncoder().encode(encrypt(data, key, spec)));
    }

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
    public byte[] encrypt(@NonNull byte[] data, @NonNull byte[] key, @NonNull GCMParameterSpec spec) throws CryptFailException {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] encryptedData = null;

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            encryptedData = cipher.doFinal(data);
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

        return Optional.ofNullable(encryptedData)
                       .orElseThrow(() -> new CryptFailException("암호화가 정상적으로 진행되지 않았습니다."));
    }

    /**
     * 문자열을 암호화 하고, 암호화 된 문자열 반환 합니다.
     *
     * @throws CryptFailException encryptedText 혹은 key, initialization vector가 null인 경우 발생
     * @throws CryptFailException 복호화 시 사용한 키가, 암호화 할 때 사용한 키와 일치하지 않는 경우 발생
     * @throws CryptFailException 암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도할 경우 발생
     * @throws CryptFailException %JAVA_HOME%\jre\lib\security\cacerts 파일이 존재하지 않거나 내부에 데이터가 존재하지 않는 경우 발생
     * @throws CryptFailException 암호화 키 값이 각각 16/24/32 byte가 아니거나, 키 값이 16 byte를 초과하면서 무제한 강도 정책이 활성화 되지 않은 경우 발생
     * @throws CryptFailException 지원되지 않거나, 부정확한 포맷으로 패딩된 데이터 암복호화를 시도하려고 할 때 발생
     * @param encryptedText 암호화 된 문자열
     * @param key 복호화 시, 사용할 키
     * @param iv 초기화 벡터
     * @return 복호화 된 문자열
     */
    public String decrypt(@NonNull String encryptedText, @NonNull byte[] key, @NonNull GCMParameterSpec spec) throws CryptFailException {
        byte[] data = Base64.getDecoder().decode(encryptedText.getBytes());
        return new String(decrypt(data, key, spec));
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
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull byte[] key, @NonNull GCMParameterSpec spec) throws CryptFailException {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] decryptedData = null;

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            decryptedData = cipher.doFinal(encryptedData);
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

        return Optional.ofNullable(decryptedData)
                       .orElseThrow(() -> new CryptFailException("복호화가 정상적으로 진행되지 않았습니다."));
    }

    /**
     * AES/CBC 알고리즘에서 사용할 초기화 벡터 값을 생성합니다.
     *
     * @param securityStrength 보안 강도: {@link SecurityStrength} 참조
     * @return 생성된 초기화 벡터
     */
    public GCMParameterSpec generateGCMParameterSpec() {
        RandomValue rv = new RandomValue();
        rv.generate(SecurityStrength.HIGH, 12);
        return new GCMParameterSpec(GCM_TAG_LENGTH * 8, rv.getBytes());
    }
}
