package dev.retrotv.crypt.twe.rsa;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.crypt.exception.WrongPaddingException;
import dev.retrotv.crypt.twe.KeyPairGenerator;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.enums.Padding;
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static dev.retrotv.enums.Padding.*;

/**
 * RSA 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public abstract class RSACipher implements TwoWayEncryption, KeyPairGenerator {
    protected static final Logger log = LogManager.getLogger();

    private static final String NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE =
            "NoSuchAlgorithmException: "
          + "\n지원하지 않는 암호화 알고리즘 입니다.";

    protected int keyLen;
    protected Algorithm algorithm;
    protected Padding padding = OAEP_WITH_SHA1_MGF1_PADDING;

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull Key publicKey, AlgorithmParameterSpec spec) throws CryptFailException {
        return encrypt(data, publicKey);
    }

    public byte[] encrypt(@NonNull byte[] data, @NonNull Key publicKey) throws CryptFailException {
        String algorithmName = algorithm.label() + "/" + padding.label();
        log.debug("선택된 알고리즘: {}", algorithmName);

        if ((publicKey.getEncoded().length * 8) == 1024) {
            log.info("key 길이는 2048bit 이상을 권장합니다.");
        }

        if (padding == PKCS1_PADDING) {
            log.info("PKCS#1 Padding 기법은 오라클 패딩 공격에 취약합니다.\n호환성이 목적이 아니라면 보안을 위해, 패딩 방식 변경을 고려하십시오.");
        }

        try {
            Cipher cipher = Cipher.getInstance(algorithmName);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            throw new CryptFailException("InvalidKeyException: \n유효하지 않은 키 입니다.\nRSA 암호화 방식에서 지원하는 키 길이인지 확인하십시오.");
        } catch (IllegalBlockSizeException e) {
            throw new CryptFailException("IllegalBlockSizeException: \n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.");
        } catch (BadPaddingException e) {
            throw new CryptFailException("BadPaddingException: \n암호화 시 사용한 키와 일치하지 않습니다.");
        } catch (NoSuchPaddingException e) {
            throw new CryptFailException("NoSuchPaddingException: \n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key privateKey, AlgorithmParameterSpec spec) throws CryptFailException {
        return decrypt(encryptedData, privateKey);
    }

    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key privateKey) throws CryptFailException {
        String algorithmName = algorithm.label() + "/" + padding.label();
        log.debug("선택된 알고리즘: {}", algorithmName);

        try {
            Cipher cipher = Cipher.getInstance(algorithmName);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return cipher.doFinal(encryptedData);
        } catch (InvalidKeyException e) {
            throw new CryptFailException("InvalidKeyException: \n유효하지 않은 키 입니다.\nRSA 암호화 방식에서 지원하는 키 길이인지 확인하십시오.");
        } catch (IllegalBlockSizeException e) {
            throw new CryptFailException("IllegalBlockSizeException: \n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.");
        } catch (BadPaddingException e) {
            throw new CryptFailException("BadPaddingException: \n암호화 시 사용한 키와 일치하지 않습니다.");
        } catch (NoSuchPaddingException e) {
            throw new CryptFailException("NoSuchPaddingException: \n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    @Override
    public KeyPair generateKeyPair() throws KeyGenerateException {
        try {
            java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLen, new SecureRandom());

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerateException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    public void dataPadding(Padding padding) {
        if (padding != PKCS1_PADDING && padding != OAEP_WITH_SHA1_MGF1_PADDING && padding != OAEP_WITH_SHA256_MGF1_PADDING) {
            throw new WrongPaddingException();
        }

        this.padding = padding;
    }
}