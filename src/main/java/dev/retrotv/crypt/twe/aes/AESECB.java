package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.random.SecurityStrength;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * AES/ECB 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public abstract class AESECB implements TwoWayEncryption {

    //AES/ECB/PKCS5Padding encryption
    private static final String BAD_PADDING_EXCEPTION_MESSAGE =
            "BadPaddingException: "
                    + "암호화 시 사용한 키와 일치하지 않습니다.";

    private static final String ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE =
            "IllegalBlockSizeException: "
                    + "암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.";

    private static final String INVALID_KEY_EXCEPTION_MESSAGE =
            "InvalidKeyException: "
                    + "1. 암호화 키는 각각 16/24/32 byte 길이의 키만 사용할 수 있습니다."
                    + "2. JDK 8u161 이전 버전 및 Oracle JDK를 사용하는 경우, 16 byte 이상의 키 사용이 제한될 수 있습니다."
                    + "\n   이에 대해서는 InvalidKeyException 무제한 강도 정책(Unlimited Strength Jurisdiction Policy)을 참조하십시오.";

    private static final String NO_SUCH_PADDING_EXCEPTION_MESSAGE =
            "NoSuchPaddingException: "
                    + "지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.";

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException data 혹은 key가 null인 경우 발생
     * @throws CryptFailException 복호화 시 사용한 키가, 암호화 할 때 사용한 키와 일치하지 않는 경우 발생
     * @throws CryptFailException 암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도할 경우 발생
     * @throws CryptFailException %JAVA_HOME%\jre\lib\security\cacerts 파일이 존재하지 않거나 내부에 데이터가 존재하지 않는 경우 발생
     * @throws CryptFailException 암호화 키 값이 각각 16/24/32 byte가 아니거나, 키 값이 16 byte를 초과하면서 무제한 강도 정책이 활성화 되지 않은 경우 발생
     * @throws CryptFailException 지원되지 않거나, 부정확한 포맷으로 패딩된 데이터 암복호화를 시도하려고 할 때 발생
     * @param data 암호화 할 데이터
     * @param key 암호화 시, 사용할 키
     * @return 암호화 된 데이터
     */
    @Override
    public byte[] encrypt(byte[] data, byte[] key) {
        Optional.ofNullable(data).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        Optional.ofNullable(key).orElseThrow(() ->
                new CryptFailException("암호화 시, 사용할 키가 존재하지 않습니다."));

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] encryptedData = null;

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encryptedData = cipher.doFinal(data);
        } catch (BadPaddingException e) {
            throw new CryptFailException(BAD_PADDING_EXCEPTION_MESSAGE, e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptFailException(ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (NoSuchPaddingException e) {
            throw new CryptFailException(NO_SUCH_PADDING_EXCEPTION_MESSAGE, e);
        } catch (NoSuchAlgorithmException ignored) { }

        return Optional.ofNullable(encryptedData)
                .orElseThrow(() -> new CryptFailException("암호화가 정상적으로 진행되지 않았습니다."));
    }

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @throws CryptFailException data 혹은 key가 null인 경우 발생
     * @throws CryptFailException 복호화 시 사용한 키가, 암호화 할 때 사용한 키와 일치하지 않는 경우 발생
     * @throws CryptFailException 암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도할 경우 발생
     * @throws CryptFailException %JAVA_HOME%\jre\lib\security\cacerts 파일이 존재하지 않거나 내부에 데이터가 존재하지 않는 경우 발생
     * @throws CryptFailException 암호화 키 값이 각각 16/24/32 byte가 아니거나, 키 값이 16 byte를 초과하면서 무제한 강도 정책이 활성화 되지 않은 경우 발생
     * @throws CryptFailException 지원되지 않거나, 부정확한 포맷으로 패딩된 데이터 암복호화를 시도하려고 할 때 발생
     * @param encryptedData 암호화 된 데이터
     * @param key 복호화 시, 사용할 키
     * @return 복호화 된 데이터
     */
    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] key) {
        Optional.ofNullable(encryptedData).orElseThrow(() ->
                new CryptFailException("복호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        Optional.ofNullable(key).orElseThrow(() ->
                new CryptFailException("복호화 시, 사용할 키가 존재하지 않습니다."));

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] decryptedData = null;

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            decryptedData = cipher.doFinal(encryptedData);
        } catch (BadPaddingException e) {
            throw new CryptFailException(BAD_PADDING_EXCEPTION_MESSAGE, e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptFailException(ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (NoSuchPaddingException e) {
            throw new CryptFailException(NO_SUCH_PADDING_EXCEPTION_MESSAGE, e);
        } catch (NoSuchAlgorithmException ignored) { }

        return Optional.ofNullable(decryptedData)
                .orElseThrow(() -> new CryptFailException("복호화가 정상적으로 진행되지 않았습니다."));
    }

    @Override
    abstract public String generateKey(SecurityStrength securityStrength);
}
