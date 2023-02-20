package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.twe.Key;

public class AESCBC128 extends AESCBC {

    @Override
    public String generateKey() {
        return Key.generate(Algorithm.AES128);
    }
}
