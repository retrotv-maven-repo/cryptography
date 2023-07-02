package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACBC128 extends LEACBC {

    public LEACBC128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.LEACBC128_PADDING;
    }
}
