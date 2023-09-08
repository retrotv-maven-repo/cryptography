package dev.retrotv.crypto.twe.rsa;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.twe.DigitalSignature;
import dev.retrotv.enums.SignatureAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.*;

import static dev.retrotv.enums.SignatureAlgorithm.SHA1;

public class RSASignature implements DigitalSignature {
    private static final Logger log = LogManager.getLogger();

    private final SignatureAlgorithm algorithm;

    public RSASignature() {
        this.algorithm = SHA1;
    }

    public RSASignature(SignatureAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    private static final String NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE =
            "NoSuchAlgorithmException: "
          + "\n지원하지 않는 암호화 알고리즘 입니다.";

    private static final String INVALID_KEY_EXCEPTION_MESSAGE =
            "InvalidKeyException: "
          + "\n암호화 키는 DES의 경우 8byte, Triple DES의 경우 24byte 길이의 키만 사용할 수 있습니다.";

    private static final String SIGNATURE_EXCEPTION_MESSAGE =
            "SignatureException: "
          + "\n서명이 유효하지 않습니다.";

    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(algorithm.label());
            signature.initSign(privateKey);
            signature.update(data);

            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptoFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (SignatureException e) {
            throw new CryptoFailException(SIGNATURE_EXCEPTION_MESSAGE, e);
        }
    }

    @Override
    public boolean verify(byte[] originalData, byte[] encryptedData, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance(algorithm.label());
            signature.initVerify(publicKey);
            signature.update(originalData);

            return signature.verify(encryptedData);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        } catch (InvalidKeyException e) {
            throw new CryptoFailException(INVALID_KEY_EXCEPTION_MESSAGE, e);
        } catch (SignatureException e) {
            throw new CryptoFailException(SIGNATURE_EXCEPTION_MESSAGE, e);
        }
    }
}
