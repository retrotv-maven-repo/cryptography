package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.twe.Key;

public class AESCBC192 extends AESCBC {

    @Override
    public String generateKey() {
        return Key.generate(Algorithm.AES192);
    }

    @Override
    public String generateInitializationVector() {
        return null;
    }
}
