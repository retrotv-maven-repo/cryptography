package dev.retrotv.crypt.twe.rsa;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.DigitalSignature;
import dev.retrotv.enums.HashAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.*;

import static dev.retrotv.enums.HashAlgorithm.SHA1;

public class RSASignature implements DigitalSignature {
    private static final Logger log = LogManager.getLogger();

    private final HashAlgorithm algorithm;

    public RSASignature() {
        this.algorithm = SHA1;
    }

    public RSASignature(HashAlgorithm algorithm) {
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

    @Override
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
}
