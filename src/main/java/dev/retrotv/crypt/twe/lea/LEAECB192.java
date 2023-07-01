package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAECB192 extends LEAECB {

    public LEAECB192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.LEAECB192_PADDING;
    }
}
