package dev.retrotv.crypto.twe.rsa;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.exception.WrongPaddingException;
import dev.retrotv.crypto.twe.TwoWayEncryption;
import dev.retrotv.enums.CipherAlgorithm;
import dev.retrotv.enums.Padding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import static dev.retrotv.enums.CipherAlgorithm.RSA;
import static dev.retrotv.enums.Padding.*;

/**
 * RSA 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class RSACipher implements TwoWayEncryption {
    private static final Logger log = LogManager.getLogger();

    private static final String NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE =
            "NoSuchAlgorithmException: "
          + "\n지원하지 않는 암호화 알고리즘 입니다.";

    private final CipherAlgorithm algorithm;
    private Padding padding = OAEP_WITH_SHA1_MGF1_PADDING;

    public RSACipher() {
        this.algorithm = RSA;
    }

    @Override
    public byte[] encrypt(byte[] data, Key publicKey, AlgorithmParameterSpec spec) {
        return encrypt(data, publicKey);
    }

    public byte[] encrypt(byte[] data, Key publicKey) {
        String algorithmName = algorithm.label() + "/" + padding.label();

        if (padding == PKCS1_PADDING) {
            log.info("PKCS#1 Padding 기법은 오라클 패딩 공격에 취약합니다.\n호환성이 목적이 아니라면 보안을 위해, 패딩 방식 변경을 고려하십시오.");
        }

        try {
            Cipher cipher = Cipher.getInstance(algorithmName);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            throw new CryptoFailException("InvalidKeyException: \n유효하지 않은 키 입니다.\nRSA 암호화 방식에서 지원하는 키 길이인지 확인하십시오.");
        } catch (IllegalBlockSizeException e) {
            throw new CryptoFailException("IllegalBlockSizeException: \n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.");
        } catch (BadPaddingException e) {
            throw new CryptoFailException("BadPaddingException: \n암호화 시 사용한 키와 일치하지 않습니다.");
        } catch (NoSuchPaddingException e) {
            throw new CryptoFailException("NoSuchPaddingException: \n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, Key privateKey, AlgorithmParameterSpec spec) {
        return decrypt(encryptedData, privateKey);
    }

    public byte[] decrypt(byte[] encryptedData, Key privateKey) {
        String algorithmName = algorithm.label() + "/" + padding.label();
        log.debug("선택된 알고리즘: {}", algorithmName);

        try {
            Cipher cipher = Cipher.getInstance(algorithmName);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return cipher.doFinal(encryptedData);
        } catch (InvalidKeyException e) {
            throw new CryptoFailException("InvalidKeyException: \n유효하지 않은 키 입니다.\nRSA 암호화 방식에서 지원하는 키 길이인지 확인하십시오.");
        } catch (IllegalBlockSizeException e) {
            throw new CryptoFailException("IllegalBlockSizeException: \n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.");
        } catch (BadPaddingException e) {
            throw new CryptoFailException("BadPaddingException: \n암호화 시 사용한 키와 일치하지 않습니다.");
        } catch (NoSuchPaddingException e) {
            throw new CryptoFailException("NoSuchPaddingException: \n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    public void dataPadding(Padding padding) {
        if (padding != PKCS1_PADDING && padding != OAEP_WITH_SHA1_MGF1_PADDING && padding != OAEP_WITH_SHA256_MGF1_PADDING) {
            throw new WrongPaddingException();
        }

        this.padding = padding;
    }
}