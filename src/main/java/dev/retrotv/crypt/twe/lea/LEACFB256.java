package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACFB256 extends LEACFB {

    public LEACFB256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.LEACFB256_NO_PADDING;
    }
}
