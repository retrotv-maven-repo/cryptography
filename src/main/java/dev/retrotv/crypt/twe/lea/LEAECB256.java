package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAECB256 extends LEAECB {

    public LEAECB256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.LEAECB256_PADDING;
    }
}
