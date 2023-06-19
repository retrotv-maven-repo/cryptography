package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.enums.SecurityStrength;

public class AESECB192 extends AESECB {

    @Override
    public String generateKey(SecurityStrength securityStrength) {
        return RandomValue.generate(securityStrength, 24);
    }
}
