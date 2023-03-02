package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

public class AESCBC192 extends AESCBC {

    @Override
    public String generateKey(SecurityStrength securityStrength) {
        return RandomValue.generate(securityStrength, 24);
    }

    @Override
    public String generateInitializationVector(SecurityStrength securityStrength) {
        return RandomValue.generate(securityStrength, 16);
    }
}
