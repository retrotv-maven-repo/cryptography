package dev.retrotv.crypt.twe.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RSA1024 extends RSA {

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024, new SecureRandom());

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException ignored) { return null; }
    }
}
