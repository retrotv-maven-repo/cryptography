package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESGCM256 extends AESGCM {

    public AESGCM256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.AESGCM256_NO_PADDING;
    }
}
