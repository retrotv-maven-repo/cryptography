package dev.retrotv.crypt.aes;

import dev.retrotv.crypt.random.Algorithm;
import dev.retrotv.crypt.random.Key;

public class AESCBC192 extends AESCBC {

    @Override
    public String generateKey() {
        return Key.generate(Algorithm.AES192);
    }
}
