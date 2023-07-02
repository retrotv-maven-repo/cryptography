package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESGCM128 extends AESGCM {

    public AESGCM128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.AESGCM128_NO_PADDING;
    }
}
