package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACFB192 extends LEACFB {

    public LEACFB192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.LEACFB192_NO_PADDING;
    }
}
