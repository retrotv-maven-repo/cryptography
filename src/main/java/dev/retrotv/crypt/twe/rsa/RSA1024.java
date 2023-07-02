package dev.retrotv.crypt.twe.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import dev.retrotv.crypt.exception.KeyGenerateException;

public class RSA1024 extends RSA {

    @Override
    public KeyPair generateKeyPair() throws KeyGenerateException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024, new SecureRandom());

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerateException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }
}
