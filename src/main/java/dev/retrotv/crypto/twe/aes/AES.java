package dev.retrotv.crypto.twe.aes;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.twe.TwoWayEncryption;
import dev.retrotv.utils.SecureRandomUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import dev.retrotv.crypto.twe.KeyGenerator;
import dev.retrotv.enums.*;

import static dev.retrotv.enums.Padding.*;
import static dev.retrotv.enums.CipherAlgorithm.AESECB;

public abstract class AES implements TwoWayEncryption, KeyGenerator {
    protected static final Logger log = LogManager.getLogger();

    protected int keyLen;
    protected CipherAlgorithm algorithm;
    protected Padding padding = NO_PADDING;

    protected static final String BAD_PADDING_EXCEPTION_MESSAGE =
            "BadPaddingException: "
          + "\n암호화 시 사용한 키와 일치하지 않습니다.";

    protected static final String ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE =
            "IllegalBlockSizeException: "
          + "\n1. 암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오."
          + "\n2. 데이터 패딩이 필요한 운영모드(ECB, CBC)를 사용할 경우, 데이터가 정상적으로 패딩되었는지 확인하십시오.";

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
    public byte[] encrypt(byte[] data, Key key, AlgorithmParameterSpec spec) throws CryptoFailException {
        String algorithmName = algorithm.label() + "/" + padding.label();

        if (algorithm == AESECB && data.length > keyLen) {
            log.info("ECB 블록암호 운영모드는 대용량 데이터를 처리하는데 적합하지 않습니다.");
        }

        if (padding == PKCS5_PADDING) {
            log.info("PKCS#5 Padding 기법은 오라클 패딩 공격에 취약합니다.");
            log.info("호환성이 목적이 아니라면, 보안을 위해 패딩이 불필요한 블록 암호화 운영모드 사용을 고려하십시오.");
        }

        try {
            log.debug("선택된 알고리즘: {}", algorithmName);
            Cipher cipher = Cipher.getInstance(algorithmName);

            if (algorithm == AESECB) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);
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
            log.debug("선택된 알고리즘: {}", algorithmName);
            Cipher cipher = Cipher.getInstance(algorithmName);

            if (algorithm == AESECB) {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, spec);
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

    @Override
    public Key generateKey() {
        return new SecretKeySpec(SecureRandomUtil.generate(keyLen / 8), "AES");
    }

    /**
     * 데이터를 패딩하도록 설정합니다.
     * 기본적으로 PKCS#5 Padding을 사용합니다.
     */
    public void dataPadding() {
        padding = PKCS5_PADDING;
    }
}
