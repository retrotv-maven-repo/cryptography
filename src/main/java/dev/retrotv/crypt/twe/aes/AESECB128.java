package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.twe.Key;

public class AESECB128 extends AESECB {

    @Override
    public String generateKey() {
        return Key.generate(Algorithm.AES128);
    }
}
