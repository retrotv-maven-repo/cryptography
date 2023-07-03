package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACFB128 extends LEACFB {

    public LEACFB128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.LEACFB128_NO_PADDING;
    }
}
