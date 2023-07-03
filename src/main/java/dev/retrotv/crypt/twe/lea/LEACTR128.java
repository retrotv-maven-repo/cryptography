package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACTR128 extends LEACTR {

    public LEACTR128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.LEACTR128_NO_PADDING;
    }
}
