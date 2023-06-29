package dev.retrotv.crypt.twe.rsa;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.DigitalSignature;
import dev.retrotv.utils.CommonMessageUtil;
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public abstract class RSA implements DigitalSignature {
    protected static final Logger log = LogManager.getLogger();
    protected static final CommonMessageUtil commonMessageUtil = new CommonMessageUtil();

    private static final String NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE =
            "NoSuchAlgorithmException: "
          + "\n지원하지 않는 암호화 알고리즘 입니다.";

    protected static final String INVALID_KEY_EXCEPTION_MESSAGE =
            "InvalidKeyException: "
          + "\n암호화 키는 DES의 경우 8byte, Triple DES의 경우 24byte 길이의 키만 사용할 수 있습니다.";

    private static final String SIGNATURE_EXCEPTION_MESSAGE =
            "SignatureException: "
          + "\n서명이 유효하지 않습니다.";

    public byte[] encrypt(@NonNull byte[] data, @NonNull byte[] key, byte[] iv) throws CryptFailException {
        return encrypt(data, key);
    }

    public byte[] encrypt(@NonNull byte[] data, @NonNull byte[] key) throws CryptFailException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            // "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"는 "RSA/None/OAEPWITHSHA-256ANDMGF1PADDING"와 동일하다.
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            throw new CryptFailException("InvalidKeyException: \n유효하지 않은 키 입니다.\nRSA 암호화 방식에서 지원하는 키 길이인지 확인하십시오.");
        } catch (IllegalBlockSizeException e) {
            throw new CryptFailException("IllegalBlockSizeException: \n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.");
        } catch (BadPaddingException e) {
            throw new CryptFailException("BadPaddingException: \n암호화 시 사용한 키와 일치하지 않습니다.");
        } catch (InvalidKeySpecException e) {
            throw new CryptFailException("InvalidKeySpecException: \n유효하지 않은 키 스펙 입니다.\nJAVA에서는 PrivateKey 생성 시, PKCS#8 방식의 키 스펙만을 지원합니다.");
        } catch (NoSuchPaddingException e) {
            throw new CryptFailException("NoSuchPaddingException: \n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull byte[] key, byte[] iv) throws CryptFailException {
        return decrypt(encryptedData, key);
    }

    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull byte[] key) throws CryptFailException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return cipher.doFinal(encryptedData);
        } catch (InvalidKeyException e) {
            throw new CryptFailException("InvalidKeyException: \n유효하지 않은 키 입니다.\nRSA 암호화 방식에서 지원하는 키 길이인지 확인하십시오.");
        } catch (IllegalBlockSizeException e) {
            throw new CryptFailException("IllegalBlockSizeException: \n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.");
        } catch (BadPaddingException e) {
            throw new CryptFailException("BadPaddingException: \n암호화 시 사용한 키와 일치하지 않습니다.");
        } catch (InvalidKeySpecException e) {
            throw new CryptFailException("InvalidKeySpecException: \n유효하지 않은 키 입니다.");
        } catch (NoSuchPaddingException e) {
            throw new CryptFailException("NoSuchPaddingException: \n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }

    public byte[] sign(byte[] data, PrivateKey privateKey) throws CryptFailException {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (SignatureException e) {
            throw new CryptFailException(SIGNATURE_EXCEPTION_MESSAGE, e);
        }
    }

    public boolean verify(byte[] originalData, byte[] encryptedData, PublicKey publicKey) throws CryptFailException {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(originalData);
    
            return signature.verify(encryptedData);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (SignatureException e) {
            throw new CryptFailException(SIGNATURE_EXCEPTION_MESSAGE, e);
        }
    }

    abstract public KeyPair generateKeyPair();
}