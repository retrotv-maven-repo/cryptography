package dev.retrotv.crypt.twe.rsa;

import java.security.*;

import dev.retrotv.crypt.exception.KeyGenerateException;

public class RSA2048 extends RSA {

    @Override
    public KeyPair generateKeyPair() throws KeyGenerateException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, new SecureRandom());

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerateException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }
}
