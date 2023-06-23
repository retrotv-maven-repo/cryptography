package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.enums.SecurityStrength;

public class AESGCM192 extends AESGCM {

    @Override
    public byte[] generateKey(SecurityStrength securityStrength) {
        RandomValue rv = new RandomValue();
        rv.generate(securityStrength, 24);
        return rv.getBytes();
    }
}
