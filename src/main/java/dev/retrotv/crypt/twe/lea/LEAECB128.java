package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAECB128 extends LEAECB {

    public LEAECB128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.LEAECB128_PADDING;
    }
}
