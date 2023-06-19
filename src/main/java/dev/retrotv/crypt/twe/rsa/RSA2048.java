package dev.retrotv.crypt.twe.rsa;

import java.security.*;

public class RSA2048 extends RSA {

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, new SecureRandom());

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException ignored) { return null; }
    }
}
