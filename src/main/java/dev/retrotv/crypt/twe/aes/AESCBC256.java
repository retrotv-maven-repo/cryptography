package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;
import dev.retrotv.crypt.twe.Key;

public class AESCBC256 extends AESCBC {

    @Override
    public String generateKey(SecurityStrength securityStrength) {
        return Key.generate(securityStrength, Algorithm.AES256);
    }

    @Override
    public String generateInitializationVector(SecurityStrength securityStrength) {
        return RandomValue.generate(securityStrength, 16);
    }
}
