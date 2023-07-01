package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACBC192 extends LEACBC {

    public LEACBC192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.LEACBC192_PADDING;
    }
}
